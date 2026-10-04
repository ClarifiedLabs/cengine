#!/usr/bin/env python3
"""Engine-free mock CLI protocol tests. NEVER invoke Docker, Go, helpers or VMs."""
import copy
import importlib.util
import io
import json
import os
import re
import subprocess
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("bounded_units", ROOT / "tools/test-guest-unit-bounded.py")
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)


def events(group, names, skip=None):
    package = "dev.cengine/guest/internal/" + group
    rows = [{"Action": "start", "Package": package}]
    for name in sorted(names):
        rows += [{"Action": "run", "Package": package, "Test": name},
                 {"Action": "skip" if name == skip else "pass", "Package": package, "Test": name}]
    rows.append({"Action": "pass", "Package": package})
    return b"\n".join(runner.encode(row) for row in rows) + b"\n"


def distribution():
    paths = ["bin/go", "pkg/tool/linux_arm64/compile", "pkg/tool/linux_arm64/asm", "pkg/tool/linux_arm64/link"]
    paths += ["src/file-%03d.go" % n for n in range(105)]
    return b"".join(b"a" * 64 + b"  /usr/local/go/" + p.encode() + b"\0" for p in sorted(paths))


def tree(root):
    files = {n: (ROOT / n).read_bytes() for n in (runner.POLICY, runner.SUPERVISOR)}
    files.update({runner.TOOL: b"# frozen runner fixture\n", "Tests/Compatibility/managed_fuse_artifact.py": b"# frozen utility\n",
                  "Tests/Compatibility/helper_fixture_lifetime.py": b"# frozen claim policy\n",
                  "Tests/Compatibility/harness.py": b"# frozen claim dependency\n",
                  "Guest/go.mod": b"module dev.cengine/guest\n", "Guest/go.sum": b"", "Guest/vendor/modules.txt": b"# offline\n"})
    files.update({n: b"{}\n" for n in runner.FIXTURES})
    names = {"storageauthority": {"TestOpenExpectedMismatchLeavesJournalIdentical", "TestStorageSchemaVersions"},
             "storageidentity": {"TestLinuxKernelIdentity"}, "storagefuse": runner.NATIVE,
             "storageworker": {"TestOwnedExitAndSignal", "TestChildDiesWithCreatingParent"},
             "storageboot": {"TestLifecycleBootSharedFixture", "TestHeldWorkerRootRejectsNilAndHostTmpfs"}}
    for group, tests in names.items():
        files["Guest/internal/" + group + "/unit_linux_test.go"] = ("//go:build linux\npackage test\nimport \"testing\"\n" +
            "\n".join("func " + n + "(t *testing.T) {}" for n in tests)).encode()
    for name, raw in files.items():
        path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    return names


class FakeCLI:
    """A transport double, not a policy double: real policy/coverage guards run."""
    def __init__(self, root, args, mode="pass"):
        self.root, self.args, self.mode = root, args, mode
        self.groups, self.command = runner.suite_groups(args.suite), runner.suite_command(args.suite)
        self.calls, self.value, self.started, self.removed = [], None, False, False
        self.image = {"Id": args.image_id, "RepoDigests": [runner.inputs.BUILDER], "Os": "linux", "Architecture": "arm64",
                      "Config": {"Env": ["PATH=/usr/local/go/bin:/usr/bin:/bin", "GOLANG_VERSION=1.25.0"]}}
    def __call__(self, command, deadline, *, env, input_file=None, maximum=1 << 20, guard=lambda: None):
        guard()
        assert command[:5] == ["/FAKE-CLI-NEVER-EXECUTE", "--config", str(Path(self.args.destination) / "docker-config"), "--host", self.args.host]
        assert set(env) == {"PATH", "HOME", "LANG", "LC_ALL"}
        assert time.monotonic() < deadline <= self.outer_deadline - 5
        command = command[5:]; self.calls.append(command)
        if command[0] == "info":
            return runner.encode({"ID": "wrong" if self.mode == "daemon" or self.mode == "daemon-change" and self.started else self.args.daemon_id,
                                  "OSType": "linux", "Architecture": "aarch64", "CgroupVersion": "2"})
        if command[:2] == ["image", "inspect"]:
            image = copy.deepcopy(self.image)
            if self.mode == "image": image["Id"] = "sha256:" + "b" * 64
            if self.mode == "digest": image["RepoDigests"] = []
            return runner.encode([image])
        if command[0] == "create":
            def option(key): return command[command.index(key) + 1]
            name, token = option("--name"), option("--label").split("=", 1)[1]
            assert command[-len(self.command):] == self.command
            assert command[command.index("--entrypoint") + 1] == "/usr/bin/env"
            assert [command[i+1] for i, value in enumerate(command) if value == "--cap-add"] == runner.CAPS
            assert option("--memory") == option("--memory-swap") == "1g"
            assert option("--pids-limit") == "128" and option("--shm-size") == "16m"
            assert "--pull=never" in command and "--no-healthcheck" in command
            assert "/work:rw,exec,nosuid,nodev,size=768m" in command
            assert "--privileged" not in command and "--volume" not in command and "--device" not in command
            h = {"Memory": 1 << 30, "MemorySwap": 1 << 30, "NanoCpus": 2000000000, "PidsLimit": 128,
                 "ReadonlyRootfs": True, "NetworkMode": "none", "Privileged": False, "CapDrop": ["ALL"], "CapAdd": sorted("CAP_" + cap for cap in runner.CAPS),
                 "Tmpfs": runner.TMPFS, "ShmSize": 16 << 20, "LogConfig": {"Type": "none", "Config": {}},
                 "Ulimits": [{"Name": "core", "Soft": 0, "Hard": 0}, {"Name": "nofile", "Soft": 4096, "Hard": 4096}],
                 "IpcMode": "private", "CgroupnsMode": "private", "PublishAllPorts": False, "AutoRemove": False,
                 "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                 "SecurityOpt": ["no-new-privileges", "seccomp=" + (self.root / runner.POLICY).read_text()]}
            self.value = {"Id": "c" * 64, "Name": "/" + name, "Image": self.args.image_id, "HostConfig": h,
                "Config": {"Image": self.args.image_id, "User": "0:0", "Entrypoint": ["/usr/bin/env"], "Cmd": self.command,
                           "WorkingDir": "/work", "Env": self.image["Config"]["Env"], "Labels": {runner.OWNER: token},
                           "Healthcheck": {"Test": ["NONE"]}, "OpenStdin": True, "Tty": False},
                "State": {"Status": "created", "Running": False, "ExitCode": 0, "OOMKilled": False}}
            if self.mode == "policy": self.value["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
            if self.mode == "wrong-suite-command": self.value["Config"]["Cmd"] = runner.CMD
            if self.mode == "foreign": self.value["Config"]["Labels"][runner.OWNER] = "foreign"
            if self.mode == "renamed": self.value["Name"] = "/renamed-after-create"
            if self.mode == "absent": self.value = None
            if self.mode in ("ambiguous", "absent", "foreign", "renamed"): raise ValueError("ambiguous create transport")
            if self.mode == "invalid-id": return b"not-an-id"
            return b"c" * 64 + b"\n"
        if command[:2] == ["container", "inspect"]:
            if self.mode == "malformed": return b'[{"Id":1,"Id":2}]'
            return runner.encode([self.value])
        if command[0] == "start":
            assert self.value is not None and not self.started and command == ["start", "-ai", "c" * 64]
            self.started = True
            source = runner.snapshot(self.root)
            assert input_file.read() == runner.archive(source)
            if self.mode == "lock-loss":
                (Path(self.args.lock) / "pid").write_text("999999\n"); guard()
            inventory = b"".join((runner.digest(raw) + "  ./" + n).encode() + b"\0" for n, raw in sorted(source.items()))
            files = {"source.before": inventory, "source.after": inventory,
                     "toolchain.before": distribution(), "toolchain.after": distribution(), "run.status": b"0\n"}
            expected = runner.expected_tests(source, self.args.suite)
            for i, group in enumerate(self.groups):
                skip = sorted(expected[group])[0] if self.mode == "raw-skip" else None
                files["group-" + str(i) + ".jsonl"] = events(group, expected[group], skip)
                files["group-" + str(i) + ".stderr"] = b""
                files["group-" + str(i) + ".status"] = b"0\n"
            if self.mode == "extra-group": files["group-2.status"] = b"0\n"
            if self.mode == "source-change": (self.root / "Guest/go.mod").write_text("changed\n")
            if self.mode == "guest-change": files["source.after"] += b"changed"
            if self.mode == "toolchain-change": files["toolchain.after"] += b"changed"
            self.value["State"].update(Status="exited", OOMKilled=self.mode == "oom")
            if self.mode.startswith("status-"):
                filename = "run.status" if self.mode.startswith("status-run-") else "group-" + str(len(self.groups) - 1) + ".status"
                files[filename] = {"empty": b"", "nonzero": b"1\n", "not-run": b"not-run\n", "interrupted": b"interrupted\n"}[self.mode.split("-", 2)[2]]
            if self.mode in ("failed-start", "timed-out", "partial-success"):
                files["group-1.status"] = b"124\n" if self.mode == "timed-out" else b"1\n"
                files["group-1.stderr"] = b"compiler/test failure evidence\n"
                files["group-1.jsonl"] = b'{"Action":"fail"}\n'
                for i in range(2, len(self.groups)):
                    files["group-" + str(i) + ".status"] = b"not-run\n"
                    files["group-" + str(i) + ".jsonl"] = b""
                files["run.status"] = files["group-1.status"]
                if self.mode != "partial-success":
                    self.value["State"]["ExitCode"] = int(files["run.status"])
                    raise runner.CommandFailure("CLI failed", runner.archive(files), b"attached error\n", self.value["State"]["ExitCode"])
            if self.mode in ("host-timeout", "output-overflow"):
                raise runner.CommandFailure("command deadline" if self.mode == "host-timeout" else "CLI output bound",
                                            b"partial archive prefix", b"stderr before failure", None)
            return runner.archive(files)
        if command[:2] == ["container", "ls"]:
            if self.value is None or self.removed: return b""
            if self.mode == "renamed" and command[command.index("--filter") + 1].startswith("name="): return b""
            return runner.encode({"ID": self.value["Id"], "Names": self.value["Name"][1:]}) + b"\n"
        if command[0] == "rm":
            assert not (Path(self.args.destination) / "output.tar").exists(), "no output fsync before cleanup"
            assert not any(Path(self.args.destination).glob("group-*")), "no exported-member fsync before cleanup"
            assert not (Path(self.args.destination) / "inspect.cleanup.json").exists()
            assert command == ["rm", "-f", "c" * 64]
            self.removed = self.mode != "cleanup-stuck"
            return b"c" * 64 + b"\n"
        raise AssertionError("FORBIDDEN CLI COMMAND: " + repr(command))


class RunnerTests(unittest.TestCase):
    def run_fake(self, mode="pass", image_id=None, suite="default"):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); names = tree(root)
            names = {g: names[g] for g in runner.suite_groups(suite)}
            lock = root / "original.lock"; lock.mkdir(mode=0o700); (lock / "pid").write_text(str(os.getppid()) + "\n")
            args = SimpleNamespace(host="unix:///explicit/unused.sock", daemon_id=runner.inputs.BUILDER_DAEMON_ID,
                image_id=image_id or "sha256:" + "a" * 64, lock=str(lock), lock_pid=os.getppid(), destination=str(root / "receipt"),
                docker="/FAKE-CLI-NEVER-EXECUTE", suite=suite)
            cli = FakeCLI(root, args, mode); cli.outer_deadline = time.monotonic() + 300.1
            clock = time.monotonic
            with patch.object(runner.time, "monotonic", side_effect=lambda: clock() + (35 if mode == "late-start" and cli.value is not None else 0)), \
                 patch.object(runner, "ROOT", root), patch.object(runner, "run_bounded", side_effect=cli), \
                 patch.object(runner, "endpoint_stamp", side_effect=lambda p: (2 if mode == "endpoint-change" and cli.started else 1,)), \
                 patch.object(runner.claims, "launcher_lock", return_value=lock.absolute()), \
                 patch.dict(os.environ, DOCKER_HOST="tcp://FORBIDDEN", CENGINE_TEST="FORBIDDEN"), \
                 patch.object(runner.subprocess, "Popen", side_effect=AssertionError("NO PROCESSES IN CLI MOCK TESTS")), \
                 patch("sys.stdout", new_callable=io.StringIO):
                if mode == "pass": runner.run(args)
                else:
                    with self.assertRaises((ValueError, OSError)): runner.run(args)
            destination = Path(args.destination)
            self.assertTrue(lock.is_dir(), "runner must never delete the parent lock")
            self.assertEqual((destination / "receipt.json").exists(), mode == "pass")
            if mode == "pass":
                receipt = runner.loads((destination / "receipt.json").read_bytes())
                self.assertEqual(receipt["expected_tests"], {g: sorted(t) for g, t in names.items()})
                self.assertEqual(receipt["suite"], suite)
                self.assertEqual(receipt["groups"], list(names))
                self.assertEqual(receipt["command"], runner.suite_command(suite))
                self.assertEqual(receipt["group_sources"], {g: {n: h for n, h in receipt["sources"].items()
                    if n.startswith("Guest/internal/" + g + "/")} for g in names})
                self.assertTrue(all(receipt["group_sources"].values()))
                self.assertTrue(receipt["removed"]); self.assertEqual(receipt["image_id"], args.image_id)
                self.assertEqual(receipt["reference"], runner.inputs.BUILDER)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
                self.assertTrue(all(p.stat().st_mode & 0o077 == 0 for p in destination.iterdir()))
            cli.artifacts = {p.name: p.read_bytes() for p in destination.iterdir() if p.is_file()} if destination.exists() else {}
            return cli

    def test_failure_and_timeout_keep_evidence_before_exact_owner_removal(self):
        for mode in ("failed-start", "timed-out", "partial-success", "host-timeout", "output-overflow"):
            with self.subTest(mode=mode):
                cli = self.run_fake(mode)
                self.assertTrue(cli.removed)
                self.assertIn("inspect.cleanup.json", cli.artifacts)
                self.assertFalse(runner.loads(cli.artifacts["cleanup.json"])["execution_complete"])
                self.assertNotIn("receipt.json", cli.artifacts)
                if mode in ("host-timeout", "output-overflow"):
                    self.assertEqual(cli.artifacts["output.tar"], b"partial archive prefix")
                    self.assertIsNone(runner.loads(cli.artifacts["start.failure.json"])["returncode"])
                else:
                    files = runner.unpack(cli.artifacts["output.tar"])
                    self.assertIn(b'TestStorageSchemaVersions', files["group-0.jsonl"])
                    self.assertEqual(files["group-1.stderr"], b"compiler/test failure evidence\n")
                    self.assertEqual(files["group-2.status"], b"not-run\n")
                    self.assertEqual(files["group-2.jsonl"], b"")
                    self.assertEqual(files["source.before"], files["source.after"])
                    self.assertEqual(files["toolchain.before"], files["toolchain.after"])
                    self.assertNotEqual(files["run.status"], b"0\n")
                start = next(i for i, c in enumerate(cli.calls) if c[0] == "start")
                for command in cli.calls[start+1:]:
                    self.assertTrue(command[:2] in (["container", "ls"], ["container", "inspect"]) or command[0] in ("rm", "info"))

    def test_status_alone_rejects_otherwise_passing_exports(self):
        for scope in ("run", "group"):
            for value in ("empty", "nonzero", "not-run", "interrupted"):
                with self.subTest(scope=scope, value=value):
                    cli = self.run_fake("status-" + scope + "-" + value)
                    self.assertTrue(cli.removed)
                    self.assertIn("output.tar", cli.artifacts)
                    self.assertNotIn("receipt.json", cli.artifacts)

    def test_cleanup_deadline_has_separate_publication_reserve(self):
        # A transport double exhausts each cleanup command's own allowed time,
        # rather than advancing beyond the deadline it was given.
        original = FakeCLI.__call__
        clock = time.monotonic
        current = [None]
        def invoke(cli, command, deadline, **kwargs):
            if current[0] is not None and current[0] >= deadline:
                runner.require(False, "cleanup deadline")
            try:
                result = original(cli, command, deadline, **kwargs)
            except runner.CommandFailure:
                current[0] = deadline  # Consume start's entire normal budget.
                raise
            if cli.started:
                current[0] = deadline  # Exhaust cleanup commands up to parent-5.
            return result
        with patch.object(FakeCLI, "__call__", invoke), patch.object(time, "monotonic", side_effect=lambda: current[0] or clock()):
            cli = self.run_fake("host-timeout")
        self.assertIn("output.tar", cli.artifacts)
        self.assertEqual(cli.artifacts["output.tar"], b"partial archive prefix")
        self.assertFalse(runner.loads(cli.artifacts["cleanup.json"])["removed"])

    def test_late_start_refuses_to_spend_failure_export_budget(self):
        cli = self.run_fake("late-start")
        self.assertFalse(cli.started)
        self.assertTrue(cli.removed)

    def test_full_fixed_protocol_and_receipt(self):
        cli = self.run_fake()
        self.assertTrue(cli.started and cli.removed)
        self.assertEqual([c[0] for c in cli.calls].count("create"), 1)
        self.assertEqual([c[0] for c in cli.calls].count("start"), 1)

    def test_containerd_equal_image_and_manifest_ids_are_independently_pinned(self):
        image = "sha256:" + runner.inputs.BUILDER.split(":", 1)[1]
        cli = self.run_fake(image_id=image)
        self.assertTrue(cli.started and cli.removed)
        self.assertEqual(runner.loads(cli.artifacts["receipt.json"])["image_id"], image)

    def test_pins_policy_json_coverage_mutation_and_cleanup_fail_closed(self):
        for mode in ("daemon", "image", "digest", "policy", "malformed", "raw-skip", "source-change", "guest-change", "toolchain-change", "oom", "cleanup-stuck", "endpoint-change", "daemon-change"):
            with self.subTest(mode=mode):
                cli = self.run_fake(mode)
                if mode in ("daemon", "image", "digest", "policy", "malformed"): self.assertFalse(cli.started)
                if mode not in ("daemon", "image", "digest", "malformed", "cleanup-stuck", "endpoint-change", "daemon-change"): self.assertTrue(cli.removed)

    def test_ambiguous_create_exact_owner_reconciliation_and_authority_loss(self):
        for mode in ("ambiguous", "absent", "foreign", "renamed", "invalid-id", "lock-loss"):
            with self.subTest(mode=mode):
                cli = self.run_fake(mode)
                self.assertEqual(cli.removed, mode not in ("absent", "foreign", "renamed"))
                index = next(i for i, c in enumerate(cli.calls) if c[0] == ("start" if mode == "lock-loss" else "create"))
                for command in cli.calls[index+1:]:
                    self.assertTrue(command[:2] in (["container", "ls"], ["container", "inspect"]) or command[0] in ("rm", "info"))

    def test_inspect_rejects_authority_and_resource_drift(self):
        cli = self.run_fake()
        value = copy.deepcopy(cli.value); value["State"]["Status"] = "created"
        policy = runner.loads((ROOT / runner.POLICY).read_bytes())
        name, token = value["Name"][1:], value["Config"]["Labels"][runner.OWNER]
        runner.container_policy(value, cli.image, policy, name, token)
        mutations = [lambda v:v["HostConfig"].update(Privileged=True),
            lambda v:v["HostConfig"].update(Memory=2 << 30),
            lambda v:v["HostConfig"].update(Devices=[{"PathOnHost": "/dev/fuse"}]),
            lambda v:v["HostConfig"].update(Binds=["/var/run/docker.sock:/socket"]),
            lambda v:v["HostConfig"].update(SecurityOpt=["no-new-privileges", "seccomp=unconfined"]),
            lambda v:v["HostConfig"].update(Ulimits=[{"Name": "core", "Soft": 0, "Hard": 0}] * 2),
            lambda v:v["HostConfig"]["Tmpfs"].update({"/work": "rw,nosuid,nodev,size=768m"}),
            lambda v:v["Config"].update(Cmd=["sh"]),
            lambda v:v["Config"].update(Env=["CENGINE_TEST=1"])]
        for mutate in mutations:
            bad = copy.deepcopy(value); mutate(bad)
            with self.assertRaises(ValueError): runner.container_policy(bad, cli.image, policy, name, token)

    def test_exact_coverage_rejects_missing_duplicate_unknown_skip_and_bad_json(self):
        group, names = "storageauthority", {"TestStorageSchemaVersions", "TestLifecycleOpenExpectedAnchorGuard"}
        raw = events(group, names)
        self.assertEqual(runner.coverage(raw, group, names)["TestStorageSchemaVersions"], "pass")
        for bad in (events(group, {"TestStorageSchemaVersions"}), events(group, names, "TestStorageSchemaVersions"), raw + raw,
                    raw.replace(b'"pass"', b'"fail"', 1), raw.replace(b'"run"', b'"pass"', 1),
                    raw.replace(b'TestStorageSchemaVersions', b'TestUnexpected'), b'{"Action":"pass","Action":"pass"}\n', b'{}\n', b'NaN\n'):
            with self.subTest(raw=bad[:60]), self.assertRaises((ValueError, TypeError)): runner.coverage(bad, group, names)
        for group in ("storageauthority", "storageidentity", "storagefuse", "storageworker", "storageboot"):
            with self.assertRaisesRegex(ValueError, "skip"):
                runner.coverage(events(group, {"TestOne"}, "TestOne"), group, {"TestOne"})

    def test_real_frozen_names_and_seccomp_are_source_grounded(self):
        source = runner.snapshot(ROOT)
        expected = runner.expected_tests(source)
        for name in ("Tests/Compatibility/helper_fixture_lifetime.py", "Tests/Compatibility/harness.py"):
            self.assertEqual(source[name], (ROOT / name).read_bytes())
        self.assertEqual(set(expected), {"storageauthority", "storageidentity", "storagefuse"})
        self.assertFalse(any(n.startswith("Guest/internal/storage/") for n in source))
        required = {"TestOpenExpectedMismatchLeavesJournalIdentical", "TestStorageSchemaVersions",
                    "TestLifecycleOpenExpectedAnchorGuard", "TestLifecycleColdWireAndBothSignatures",
                    "TestLifecycleResumeWireAndBothSignatures", "TestLifecycleServiceResultFixture",
                    "TestLifecycleHandoffCrossLanguageVector",
                    "TestLifecycleProvenRecovery", "TestStorageCompatibilityOrdinaryAndConflictingTagsInert",
                    "TestWorkerExitDefaultAndOldProfilesInert", "TestPrepareIOPhase2ProfilesInert"}
        self.assertTrue(required <= expected["storageauthority"], required - expected["storageauthority"])
        # Native ext4 coverage remains mandatory: an unavailable fixture must
        # fail closed, not become a newly allowed skip in the bounded runner.
        native = "TestNativeLifecycleCheckpointAndTerminalSeal"
        self.assertIn(native, expected["storageauthority"])
        with self.assertRaisesRegex(ValueError, "skip"):
            runner.coverage(events("storageauthority", {native}, native), "storageauthority", {native})
        self.assertEqual(expected["storagefuse"], runner.NATIVE)
        # Every literal relative JSON fixture consumed by either current suite
        # must be present in the immutable snapshot, including lifecycle vectors.
        references = set()
        groups = set(runner.GROUPS) | set(runner.suite_groups("storage-worker"))
        for name, raw in source.items():
            parts = name.split("/")
            if len(parts) == 4 and parts[:2] == ["Guest", "internal"] and parts[2] in groups:
                for relative in re.findall(r'"(\.\./[^"\n]+\.json)"', raw.decode()):
                    fixture = str((ROOT / name).parent.joinpath(relative).resolve().relative_to(ROOT))
                    references.add(fixture)
                    self.assertEqual(source[fixture], (ROOT / fixture).read_bytes())
        self.assertEqual(references, set(runner.FIXTURES) - {"Guest/internal/workloadstorage/testdata/vectors.json"})
        policy = runner.validate_policy(source[runner.POLICY], source[runner.SUPERVISOR])
        self.assertEqual(policy["defaultAction"], "SCMP_ACT_ERRNO")
        for mutate in (lambda p:p.update(defaultAction="SCMP_ACT_ALLOW"),
                       lambda p:p["syscalls"][-1]["args"][0].update(value=0),
                       lambda p:p["syscalls"][0]["names"].append("mount")):
            bad = copy.deepcopy(policy); mutate(bad)
            with self.assertRaisesRegex(ValueError, "policy"): runner.validate_policy(runner.encode(bad), source[runner.SUPERVISOR])

    def test_untagged_default_excludes_only_known_inactive_constraints(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); tree(root)
            source = runner.snapshot(root)
            baseline = runner.expected_tests(source)
            path = "Guest/internal/storagefuse/native_fault_linux_test.go"
            for constraint in ("cengine_native_faulttest && linux && (arm64 || amd64)",
                               "cengine_native_faulttest",
                               "!linux || (!amd64 && !arm64)",
                               "!linux || (!arm64 && !amd64)",
                               "cengine_lifecycle_integration",
                               "cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat",
                               "(linux || darwin) && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat"):
                source[path] = ("//go:build " + constraint + "\n"
                                "package test\nfunc TestNativeServiceFaults(t *testing.T) {}\n").encode()
                with self.subTest(constraint=constraint):
                    self.assertEqual(runner.expected_tests(source), baseline)
            source.pop(path)
            inert = "Guest/internal/storageauthority/prepare_io_phase2_inert_test.go"
            source[inert] = ("//go:build !cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat\n"
                             "package test\nfunc TestPrepareIOPhase2ProfilesInert(t *testing.T) {}\n").encode()
            self.assertEqual(runner.expected_tests(source)["storageauthority"],
                             baseline["storageauthority"] | {"TestPrepareIOPhase2ProfilesInert"})
            # New or broadened constraints must not silently hide future tests.
            for constraint in ("linux || cengine_native_faulttest",
                               "cengine_native_faulttest && linux && future",
                               "linux || cengine_lifecycle_integration",
                               "!cengine_prepare_full_compat || future"):
                source[path] = ("//go:build " + constraint + "\npackage test\n").encode()
                with self.subTest(constraint=constraint), self.assertRaisesRegex(ValueError, "constraint"):
                    runner.expected_tests(source)

    def test_fixed_compile_profiles_include_full_or_inert_tests_exclusively(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); tree(root)
            source = runner.snapshot(root)
            for suite, group in (("default", "storageauthority"), ("storage-worker", "storageboot")):
                baseline = runner.expected_tests(source, suite)[group]
                extended = dict(source)
                for name, constraint in {
                    "Full": "cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat",
                    "FullPlatform": "(linux || darwin) && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat",
                    "Inert": "!cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat",
                }.items():
                    extended["Guest/internal/" + group + "/profile_" + name + "_test.go"] = (
                        "//go:build " + constraint + "\npackage test\nfunc TestProfile" + name + "(t *testing.T) {}\n").encode()
                with self.subTest(suite=suite):
                    added = {"TestProfileFull", "TestProfileFullPlatform"} if suite == "storage-worker" else {"TestProfileInert"}
                    self.assertEqual(runner.expected_tests(extended, suite)[group], baseline | added)
                for constraint in ("cengine_prepare_full_compat || future",
                                   "!cengine_prepare_full_compat || future",
                                   "linux && cengine_prepare_full_compat"):
                    extended["Guest/internal/" + group + "/unknown_test.go"] = (
                        "//go:build " + constraint + "\npackage test\n").encode()
                    with self.subTest(suite=suite, constraint=constraint), self.assertRaisesRegex(ValueError, "constraint"):
                        runner.expected_tests(extended, suite)

    def test_source_bounds_links_embed_and_frozen_declarations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); tree(root)
            source = runner.snapshot(root)
            self.assertIn("Guest/vendor/modules.txt", source)
            for i in range(4): (root / ("Guest/irrelevant-" + str(i))).write_text("ignored")
            with patch.object(runner, "MAX_ENTRIES", 3), self.assertRaisesRegex(ValueError, "traversal bound"):
                runner.snapshot(root)
            test = root / "Guest/a.go"
            for body in (b"//go:embed missing\n", b"x" * 100):
                test.write_bytes(body)
                with patch.object(runner, "MAX_SOURCE", 1), self.assertRaisesRegex(ValueError, "bound|embed"): runner.snapshot(root)
            test.unlink(); test.symlink_to(root / "Guest/go.mod")
            with self.assertRaisesRegex(ValueError, "link"): runner.snapshot(root)
            test.unlink(); os.link(root / "Guest/go.mod", test)
            with self.assertRaisesRegex(ValueError, "single-link"): runner.snapshot(root)
            test.unlink(); os.mkfifo(test)
            with self.assertRaisesRegex(ValueError, "regular"): runner.snapshot(root)
            test.unlink()
            source["Guest/internal/storageauthority/comments_test.go"] = b'package test\n// func TestCommentOnly(t *testing.T) {}\nvar x = `func TestCommentOnly(t *testing.T) {}`\n'
            self.assertNotIn("TestCommentOnly", runner.expected_tests(source)["storageauthority"])
            source["Guest/internal/storageauthority/future_test.go"] = b'//go:build experimental\npackage test\n'
            with self.assertRaisesRegex(ValueError, "constraint"): runner.expected_tests(source)

    def test_parent_lock_pin_and_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "original"; path.mkdir(mode=0o700); (path / "pid").write_text(str(os.getppid()) + "\n")
            with patch.object(runner.claims, "launcher_lock", return_value=path.absolute()):
                with self.assertRaisesRegex(ValueError, "parent"): runner.OriginalLock(path, 1)
                lock = runner.OriginalLock(path, os.getppid())
                try:
                    lock.check(); path.rename(path.with_name("retained")); path.mkdir(mode=0o700)
                    (path / "pid").write_text(str(os.getppid()) + "\n")
                    with self.assertRaisesRegex(ValueError, "replaced"): lock.check()
                finally: lock.close()

    def test_no_arbitrary_selector_or_environment_cli(self):
        parser = runner.argument_parser()
        args = ["--host", "unix:///explicit/socket", "--daemon-id", runner.inputs.BUILDER_DAEMON_ID,
                "--image-id", "sha256:" + "a"*64, "--lock", "/original", "--lock-pid", "123", "--destination", "/new"]
        for extra in (["--suite", "./..."], ["--env", "CENGINE_TEST=1"], ["--tags", "cengine_prepare_full_compat"],
                      ["--cap-add", "SYS_ADMIN"], ["--command", "sh"]):
            with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit): parser.parse_args(args + extra)
        self.assertNotIn("./...", runner.SCRIPT)
        self.assertIn(runner.NATIVE_PATTERN, runner.SCRIPT)
        self.assertEqual(runner.SCRIPT.count("go test -json"), 3)
        self.assertIn("umask 077", runner.SCRIPT)
        self.assertIn("cd /work/src/Guest\n", runner.WORK_SCRIPT)
        self.assertLess(runner.WORK_SCRIPT.index("umask 022"), runner.WORK_SCRIPT.index("go test -json"))

    def test_fixed_suite_names_defaults_and_unknown_rejection(self):
        parser = runner.argument_parser()
        base = ["--host", "unix:///explicit/socket", "--daemon-id", runner.inputs.BUILDER_DAEMON_ID,
                "--image-id", "sha256:" + "a"*64, "--lock", "/original", "--lock-pid", "123", "--destination", "/new"]
        self.assertEqual(set(runner.SUITES), {"default", "storage-worker"})
        self.assertEqual(parser.parse_args(base).suite, "default")
        self.assertEqual(runner.suite_groups("default"), ("storageauthority", "storageidentity", "storagefuse"))
        self.assertEqual(runner.suite_groups("storage-worker"), ("storageworker", "storageboot"))
        for suite in runner.SUITES:
            self.assertEqual(parser.parse_args(base + ["--suite", suite]).suite, suite)
        for suite in ("all", "storageworker", "storageboot", "./...", "storage-worker;true", ""):
            with self.subTest(suite=suite):
                with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
                    parser.parse_args(base + ["--suite", suite])
                with patch.object(runner, "endpoint_stamp", side_effect=AssertionError("no endpoint access")), self.assertRaisesRegex(ValueError, "suite"):
                    runner.run(SimpleNamespace(suite=suite))
                for function in (runner.suite_scripts, runner.suite_command, runner.export_bounds):
                    with self.assertRaisesRegex(ValueError, "suite"): function(suite)

    def test_default_protocol_is_frozen_and_worker_selection_is_closed(self):
        # Literal pins freeze every command, bound and package group.
        for name, expected in {
            "WORK_SCRIPT": "753eecaaec1dee73e836f0e83e8c7cc868da32656776a885c459447d3f72f949",
            "SCRIPT": "42ad446c56f373d970c6a857c7a1c11085f116521eae5ba00a98efded06856f0",
            "CMD": "1a00f697954c1ec99ce702c8844665f008029a37aa191d067889d85c38a1db44",
            "EXPORT_BOUNDS": "5c4df1b50cc829b24f541de50bc78b31c51dfc8827c82378c2ca706e1f804871",
        }.items():
            value = getattr(runner, name)
            self.assertEqual(runner.digest(value.encode() if isinstance(value, str) else runner.encode(value)), expected)
        work, script = runner.suite_scripts("storage-worker")
        self.assertEqual(work.count("go test -json"), 2)
        self.assertEqual(work.count("-timeout=60s "), 2)
        self.assertEqual([line for line in work.splitlines() if line.startswith("go test ")], [
            "go test -json -mod=vendor -count=1 -p=1 -parallel=1 -trimpath -buildvcs=false -timeout=60s "
            "-tags=cengine_prepare_full_compat ./internal/" + group
            + " > /work/out/group-" + str(index) + ".jsonl 2> /work/out/group-" + str(index) + ".stderr || status=$?"
            for index, group in enumerate(("storageworker", "storageboot"))])
        self.assertNotIn("-tags", runner.WORK_SCRIPT)
        self.assertNotIn(" -run ", work)
        self.assertNotIn("./...", work)
        self.assertIn("timeout -k 2 210 sh -ec", script)
        self.assertEqual(runner.suite_command("storage-worker")[:-1], runner.CMD[:-1])
        self.assertNotIn("group-2", script)
        self.assertNotIn("group-3", script)

    def test_worker_receipts_bind_suite_groups_sources_and_all_results(self):
        cli = self.run_fake(suite="storage-worker")
        for name in ("plan.json", "cleanup.json", "receipt.json"):
            value = runner.loads(cli.artifacts[name])
            self.assertEqual(value["suite"], "storage-worker")
            self.assertEqual(value["groups"], ["storageworker", "storageboot"])
            self.assertEqual(set(value["group_sources"]), set(value["groups"]))
            self.assertTrue(all(value["group_sources"].values()))
        receipt = runner.loads(cli.artifacts["receipt.json"])
        self.assertEqual(set(receipt["results"]), {"storageworker", "storageboot"})
        self.assertTrue(all(result == "pass" for results in receipt["results"].values() for result in results.values()))
        files = runner.unpack(cli.artifacts["output.tar"], suite="storage-worker")
        self.assertEqual(set(files), set(runner.export_bounds("storage-worker")))
        with self.assertRaisesRegex(ValueError, "missing export"): runner.unpack(cli.artifacts["output.tar"])
        with self.assertRaisesRegex(ValueError, "member"):
            runner.unpack(self.run_fake().artifacts["output.tar"], suite="storage-worker")

    def test_worker_suite_preserves_fail_closed_checks_and_failure_identity(self):
        modes = ("daemon", "image", "digest", "policy", "wrong-suite-command", "raw-skip", "extra-group", "source-change",
                 "guest-change", "toolchain-change", "oom", "cleanup-stuck", "endpoint-change", "daemon-change",
                 "lock-loss", "failed-start", "timed-out", "partial-success", "host-timeout", "output-overflow",
                 "status-group-nonzero", "status-run-not-run")
        for mode in modes:
            with self.subTest(mode=mode):
                cli = self.run_fake(mode, suite="storage-worker")
                self.assertNotIn("receipt.json", cli.artifacts)
                if mode == "wrong-suite-command": self.assertFalse(cli.started)
                for name in ("plan.json", "cleanup.json", "start.failure.json"):
                    if name not in cli.artifacts: continue
                    value = runner.loads(cli.artifacts[name])
                    self.assertEqual(value["suite"], "storage-worker")
                    self.assertEqual(value["groups"], ["storageworker", "storageboot"])
                    self.assertTrue(all(value["group_sources"].values()))

    def test_worker_real_frozen_names_all_files_and_existing_syscall_authority(self):
        source = runner.snapshot(ROOT)
        expected = runner.expected_tests(source, "storage-worker")
        self.assertEqual(set(expected), {"storageworker", "storageboot"})
        for group, names in {
            "storageworker": {"TestChildDiesWithCreatingParent", "TestWaitGateRetainsZombieIdentity", "TestCredentialControlValidation"},
            "storageboot": {"TestHeldWorkerRootRejectsNilAndHostTmpfs", "TestLifecycleBootSharedFixture",
                            "TestLifecycleSupervisorExactRetriesLaunchOnceAndRecoverLostReply",
                            "TestLifecycleSupervisorNoStartBeforeReaped", "TestLifecycleSupervisorUnreapedFailsWithoutStart",
                            "TestLifecycleReplacementWireClosed", "TestLifecycleConsumerWireClosed",
                            "TestLifecycleConsumerSupervisorCorrelatesReplies"},
        }.items():
            self.assertTrue(names <= expected[group])
            self.assertTrue(all(result == "pass" for result in runner.coverage(events(group, expected[group]), group, expected[group]).values()))
            for name in expected[group]:
                with self.assertRaisesRegex(ValueError, "skip"):
                    runner.coverage(events(group, expected[group], name), group, expected[group])
            with self.assertRaisesRegex(ValueError, "coverage"):
                runner.coverage(events(group, expected[group] - {sorted(expected[group])[0]}), group, expected[group])
        # New declarations in either selected package cannot silently disappear.
        for group in expected:
            extended = dict(source)
            extended["Guest/internal/" + group + "/future_test.go"] = b'package test\nfunc TestFuture(t *testing.T) {}\n'
            self.assertEqual(runner.expected_tests(extended, "storage-worker")[group], expected[group] | {"TestFuture"})
            extended["Guest/internal/" + group + "/future_test.go"] = b'//go:build experimental\npackage test\n'
            with self.assertRaisesRegex(ValueError, "constraint"): runner.expected_tests(extended, "storage-worker")
        profile = runner.validate_policy(source[runner.POLICY], source[runner.SUPERVISOR])
        allowed = set(profile["syscalls"][0]["names"])
        # Linux/arm64 Poll is ppoll; Open/Readlink use *at. prctl covers both
        # PDEATHSIG and subreaper; Go's clone fallback may request CLONE_PIDFD.
        required = {"prctl", "pidfd_open", "pidfd_send_signal", "waitid", "wait4", "ppoll", "socketpair",
                    "getsockopt", "setsockopt", "getsockname", "getpeername", "sendmsg", "recvmsg", "fcntl",
                    "execve", "openat", "readlinkat", "getdents64", "fstatfs", "statx"}
        self.assertTrue(required <= allowed, required - allowed)
        clone = next(rule for rule in profile["syscalls"] if rule["names"] == ["clone"])
        self.assertEqual(clone["args"][0]["value"] & 0x1000, 0)  # CLONE_PIDFD is not denied.
        self.assertEqual(runner.CAPS, ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETUID", "SETGID", "MKNOD"])

    def test_archive_export_and_processing_deadline_guards(self):
        def expired(): runner.require(False, "cleanup reserve")
        with self.assertRaisesRegex(ValueError, "reserve"): runner.archive({"a": b"x"}, expired)
        with self.assertRaisesRegex(ValueError, "reserve"): runner.unpack(runner.archive({"a": b"x"}), expired)
        with self.assertRaisesRegex(ValueError, "reserve"):
            runner.coverage(events("storageauthority", {"TestStorageSchemaVersions"}),
                            "storageauthority", {"TestStorageSchemaVersions"}, expired)
        with self.assertRaisesRegex(ValueError, "member"): runner.unpack(runner.archive({"../escape": b"x"}))
        with patch.object(runner, "MAX_ARCHIVE", 1), self.assertRaisesRegex(ValueError, "archive bound"):
            runner.archive({"a": b"x"})
        with patch.object(runner, "MAX_OUTPUT", 1), self.assertRaisesRegex(ValueError, "output bound"):
            runner.unpack(b"xx")

    def test_exited_cli_leader_cannot_leave_pipe_holding_descendant(self):
        env = {"PATH": "/usr/bin:/bin"}
        body = "import os,time; child=os.fork(); time.sleep(5) if child == 0 else os._exit(0)"
        original = os.killpg
        with patch.object(runner.os, "killpg", wraps=original) as kill:
            with self.assertRaisesRegex(ValueError, "deadline"):
                runner.run_bounded([sys.executable, "-c", body], time.monotonic() + .2, env=env)
            self.assertEqual(kill.call_count, 1)

    def test_successful_cli_leader_cannot_leave_pipe_closed_descendant(self):
        body = ("import os,time\nchild=os.fork()\nif child == 0:\n"
                " os.close(0); os.close(1); os.close(2); time.sleep(10); os._exit(0)\n"
                "print('ok', flush=True)\n")
        original = os.killpg
        with patch.object(runner.os, "killpg", wraps=original) as kill:
            self.assertEqual(runner.run_bounded([sys.executable, "-c", body], time.monotonic() + 2,
                                               env={"PATH": "/usr/bin:/bin"}), b"ok\n")
            self.assertEqual(kill.call_count, 1)

    def test_nonzero_and_deadline_preserve_capped_transport_output(self):
        cases = [("import os; os.write(1,b'archive'); os.write(2,b'failure'); raise SystemExit(7)", 2, 1024, b"archive", 7),
                 ("import os,time; os.write(1,b'prefix'); os.write(2,b'failure'); time.sleep(10)", .2, 1024, b"prefix", None),
                 ("import os; os.write(1,b'x'*10000)", 2, 1024, b"x"*1024, None)]
        for body, seconds, maximum, output, code in cases:
            with self.subTest(code=code), self.assertRaises(runner.CommandFailure) as failure:
                runner.run_bounded([sys.executable, "-c", body], time.monotonic() + seconds,
                                   env={"PATH": "/usr/bin:/bin"}, maximum=maximum)
            self.assertEqual(failure.exception.output, output)
            if output != b"x"*1024:
                self.assertEqual(failure.exception.errors, b"failure")
                self.assertEqual(failure.exception.returncode, code)

    def test_reap_timeout_cannot_mask_captured_transport_evidence(self):
        original = runner.subprocess.Popen
        processes = []
        def spawn(*args, **kwargs):
            process = original(*args, **kwargs); processes.append(process)
            process.wait = lambda **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired(args[0], kw["timeout"]))
            return process
        try:
            with patch.object(runner.subprocess, "Popen", side_effect=spawn), self.assertRaises(runner.CommandFailure) as failure:
                runner.run_bounded([sys.executable, "-c", "import os,time; os.write(1,b'captured archive'); time.sleep(10)"],
                                   time.monotonic() + .5, env={"PATH": "/usr/bin:/bin"})
            self.assertEqual(failure.exception.output, b"captured archive")
            self.assertIn("reap deadline", str(failure.exception))
        finally:
            for process in processes:
                del process.wait
                process.wait(timeout=2)

    def test_total_export_caps_fit_transport_including_tar_overhead(self):
        for suite in runner.SUITES:
            bounds = runner.export_bounds(suite)
            self.assertLess(sum(bounds.values()) + len(bounds) * 1024 + 10240, runner.MAX_OUTPUT)

    def test_fixed_shell_exports_success_failure_and_worker_timeout_without_engine(self):
        for suite in runner.SUITES:
            with self.subTest(suite=suite):
                self.check_fixed_shell_exports(suite)

    def check_fixed_shell_exports(self, suite):
        work_script, outer_script = runner.suite_scripts(suite)
        groups = runner.suite_groups(suite)
        # Run the real fixed shell control flow with fake Go/inventories. No Go,
        # Docker, VM, host /work writes or GNU-tool installation is involved.
        for mode, expected_code in (("pass", 0), ("fail", 7), ("timeout", 124), ("oversize", 1)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); work = root / "work"; (work / "src/Guest").mkdir(parents=True)
                bindir = root / "bin"; bindir.mkdir()
                go = bindir / "go"
                go.write_text("#!" + sys.executable + "\nimport sys\ngroup=next(a for a in sys.argv if a.startswith('./internal/'))\n"
                    + "print(group, flush=True)\nprint('diagnostic '+group, file=sys.stderr, flush=True)\n"
                    + ("raise SystemExit(7 if group == " + repr("./internal/" + groups[1]) + " else 0)\n" if mode == "fail" else "")
                    + ("from pathlib import Path\nPath(" + repr(str(root / "go-ready")) + ").touch()\nimport time\ntime.sleep(10)\n" if mode == "timeout" else "")
                    + ("print('x'*(8<<20))\n" if mode == "oversize" else ""))
                go.chmod(0o700)
                timeout = bindir / "timeout"
                timeout.write_text("#!" + sys.executable + "\nimport os,signal,subprocess,sys,time\nfrom pathlib import Path\n"
                    + "p=subprocess.Popen(sys.argv[4:],start_new_session=True)\n"
                    + ("ready=Path(" + repr(str(root / "go-ready")) + ")\nlimit=time.monotonic()+5\n"
                       + "while not ready.exists() and p.poll() is None and time.monotonic()<limit: time.sleep(.01)\n"
                       if mode == "timeout" else "")
                    + "try: code=p.wait(timeout=" + (".1" if mode == "timeout" else "10") + ")\n"
                    + "except subprocess.TimeoutExpired:\n os.killpg(p.pid,signal.SIGKILL); p.wait(); code=124\n"
                    + "raise SystemExit(code)\n")
                timeout.chmod(0o700)
                size = bindir / "stat"
                size.write_text("#!" + sys.executable + "\nimport os,sys\nprint(os.stat(sys.argv[-1]).st_size)\n")
                size.chmod(0o700)
                head = bindir / "head"
                head.write_text("#!" + sys.executable + "\nraise OSError(28, 'full tmpfs: no scratch copy space')\n")
                head.chmod(0o700)
                truncate = bindir / "truncate"
                truncate.write_text("#!" + sys.executable + "\nimport sys\nwith open(sys.argv[3],'r+b') as f: f.truncate(int(sys.argv[2]))\n")
                truncate.chmod(0o700)
                dd = bindir / "dd"
                dd.write_text("#!" + sys.executable + "\nimport sys\n"
                    + "assert 'conv=notrunc' in sys.argv\n"
                    + "name=next(a[3:] for a in sys.argv if a.startswith('of='))\n"
                    + "with open(name,'r+b') as f:\n"
                    + " data=sys.stdin.buffer.read(); assert len(data)<=4096; f.write(data)\n")
                dd.chmod(0o700)
                self.assertNotIn(".capped", outer_script)
                self.assertNotIn('> /work/out/run.status', outer_script.split('status=0\ntimeout', 1)[-1])
                # Both copies are shell-quoted independently, so substitute the
                # inventory function text before rebuilding the fixed script.
                fixed = runner.STATUS_SCRIPT + "\ninventory() { printf source-inventory; }\ntoolchain_inventory() { printf toolchain-inventory; }\n"
                script = outer_script.replace(runner.shlex.quote(work_script),
                    runner.shlex.quote(work_script.replace(runner.INVENTORY_SCRIPT, fixed)))
                script = script.replace(runner.INVENTORY_SCRIPT, fixed).replace("/work", str(work))
                result = subprocess.run(["/bin/sh", "-ec", script], input=runner.archive({}), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, env={"PATH": str(bindir) + ":/usr/bin:/bin", "COPYFILE_DISABLE": "1"}, timeout=20)
                self.assertEqual(result.returncode, expected_code, result.stderr)
                files = runner.unpack(result.stdout, suite=suite)
                self.assertEqual(files["run.status"], (str(expected_code) + "\n").encode())
                self.assertEqual(files["source.before"], files["source.after"])
                self.assertEqual(files["toolchain.before"], files["toolchain.after"])
                if mode == "timeout" or mode == "fail" and suite == "default":
                    last = "group-" + str(len(groups) - 1)
                    self.assertEqual(files[last + ".status"], b"not-run\n")
                    self.assertEqual(files[last + ".jsonl"], b"")
                if mode in ("fail", "timeout"):
                    self.assertIn(b"diagnostic", files["group-0.stderr"])
                if mode == "pass":
                    self.assertEqual([files["group-" + str(i) + ".jsonl"] for i in range(len(groups))],
                                     [("./internal/" + g + "\n").encode() for g in groups])
                if mode == "fail": self.assertEqual(files["group-1.status"], b"7\n")
                if mode == "timeout": self.assertEqual(files["group-0.status"], b"interrupted\n")
                if mode == "oversize": self.assertEqual(len(files["group-0.jsonl"]), runner.export_bounds(suite)["group-0.jsonl"])

    def test_real_supervisor_bounds_using_only_python_children(self):
        env = {"PATH": "/usr/bin:/bin"}
        for body, seconds, maximum, error in (("import time; time.sleep(10)", .15, 1024, "deadline"),
                ("import sys; sys.stdout.write('x'*1000000)", 2, 1024, "output bound"),
                ("import sys; sys.stderr.write('x'*1000000)", 2, 1024, "output bound")):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                runner.run_bounded([sys.executable, "-c", body], time.monotonic() + seconds, env=env, maximum=maximum)
        with patch.object(runner.subprocess, "Popen", side_effect=AssertionError("must not spawn")):
            with self.assertRaisesRegex(ValueError, "deadline"):
                runner.run_bounded(["FORBIDDEN"], time.monotonic() - 1, env=env)
            with self.assertRaisesRegex(ValueError, "authority"):
                runner.run_bounded(["FORBIDDEN"], time.monotonic() + 1, env=env,
                                   guard=lambda: runner.require(False, "authority lost"))


if __name__ == "__main__":
    unittest.main()
