#!/usr/bin/env python3
"""Engine-free DGN-003 watchdog calibration and owned-start lifecycle regressions."""
from contextlib import contextmanager
import ast
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import test_volume_concurrency as concurrency


class Worker:
    """Real pipe, fake process: wait/kill/close ordering is observable without an engine."""
    def __init__(self, pid, events, wire=b"ready\nstarted\n", status=0, timeout=False):
        self.pid, self.events, self.status, self.timeout = pid, events, status, timeout
        self.returncode = None
        read, write = os.pipe()
        os.write(write, wire)
        os.close(write)
        self.stdout = os.fdopen(read, "rb", buffering=0)
        class Input(io.BytesIO):
            def write(inner, value):
                events.append((pid, "gate", value))
                return super().write(value)
        self.stdin = Input()

    def poll(self):
        return self.returncode

    def kill(self):
        self.events.append((self.pid, "kill"))
        self.returncode = -9

    def wait(self, timeout=None):
        self.events.append((self.pid, "wait", timeout))
        if self.timeout and timeout is not None:
            raise subprocess.TimeoutExpired("owned", timeout)
        if self.returncode is None:
            self.returncode = self.status
        return self.returncode


def container(identifier="owned", version="1.55"):
    return SimpleNamespace(id=identifier, client=SimpleNamespace(api=SimpleNamespace(
        adapters={"http+docker://": SimpleNamespace(socket_path="/unused-owned.sock")},
        _version=version, timeout=45)))


class StartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.events, self.workers = [], []
        self.addCleanup(concurrency._UNSETTLED_STARTS.discard, self.directory)

    def worker(self, **kwargs):
        worker = Worker(len(self.workers) + 100, self.events, **kwargs)
        self.workers.append(worker)
        self.addCleanup(worker.stdin.close)
        self.addCleanup(worker.stdout.close)
        return worker

    def record(self, directory, value):
        self.assertIn(directory, concurrency._UNSETTLED_STARTS)
        if value["phase"] == "start-results":
            for worker in self.workers:
                self.assertIn((worker.pid, "wait", None), self.events)
                self.assertTrue(worker.stdout.closed)
            self.events.append(("results", value["failed"]))

    def invoke(self, workers):
        with patch.object(concurrency.subprocess, "Popen", side_effect=workers) as spawn, \
             patch.object(concurrency, "_record", side_effect=self.record), \
             patch.object(concurrency.time, "monotonic", return_value=10):
            concurrency._simultaneous_start([container(str(i)) for i in range(len(workers))], self.directory)
        return spawn

    def test_partial_markers_barrier_positive_exit_actual_reap_then_record_then_unfence(self):
        workers = [self.worker(), self.worker()]
        original_read, marker = os.read, concurrency._start_marker
        def observe(process, expected, deadline):
            marker(process, expected, deadline)
            self.events.append((process.pid, "marker", expected))
        with patch.object(concurrency.os, "read", side_effect=lambda fd, n: original_read(fd, min(n, 1))), \
             patch.object(concurrency, "_start_marker", side_effect=observe):
            spawn = self.invoke(workers)
        gates = [i for i, event in enumerate(self.events) if event[1] == "gate"]
        ready = [i for i, event in enumerate(self.events) if event[1:] == ("marker", b"ready\n")]
        self.assertLess(max(ready), min(gates))
        self.assertEqual(self.events[-1], ("results", False))
        self.assertNotIn(self.directory, concurrency._UNSETTLED_STARTS)
        self.assertEqual([e[2] for e in self.events if e[1] == "wait" and e[2] is not None], [130, 130])
        self.assertTrue(all(call.kwargs["stderr"] == subprocess.DEVNULL for call in spawn.call_args_list))
        self.assertTrue(all("1.55" in call.args[0] for call in spawn.call_args_list))

    def test_missing_partial_bad_extra_success_output_and_nonzero_exit_keep_fence(self):
        for wire, status in ((b"ready\n", 0), (b"rea", 0), (b"wrong\n", 0),
                             (b"ready\nstart", 0), (b"ready\nstarted\nx", 0),
                             (b"ready\nstarted\n", 1)):
            with self.subTest(wire=wire, status=status):
                self.workers, self.events = [], []
                worker = self.worker(wire=wire, status=status)
                with self.assertRaises(concurrency.UnsettledStarts):
                    self.invoke([worker])
                self.assertIn(self.directory, concurrency._UNSETTLED_STARTS)
                self.assertIn((worker.pid, "wait", None), self.events)

    def test_timeout_kills_only_owned_children_and_reaps_without_a_timeout(self):
        first, second = self.worker(timeout=True), self.worker()
        with self.assertRaises(concurrency.UnsettledStarts):
            self.invoke([first, second])
        for worker in (first, second):
            self.assertLess(self.events.index((worker.pid, "kill")),
                            self.events.index((worker.pid, "wait", None)))
        self.assertIn(self.directory, concurrency._UNSETTLED_STARTS)

    def test_protocol_timeout_reaps_and_quarantines(self):
        worker = self.worker(wire=b"")
        with patch.object(concurrency.select, "select", return_value=([], [], [])), \
             self.assertRaises(concurrency.UnsettledStarts):
            self.invoke([worker])
        self.assertIn((worker.pid, "kill"), self.events)
        self.assertIn((worker.pid, "wait", None), self.events)
        self.assertIn(self.directory, concurrency._UNSETTLED_STARTS)

    def test_partial_spawn_failure_still_reaps_first_owned_child(self):
        worker = self.worker()
        with patch.object(concurrency.subprocess, "Popen", side_effect=[worker, OSError("spawn")]), \
             patch.object(concurrency, "_record", side_effect=self.record), \
             self.assertRaises(concurrency.UnsettledStarts):
            concurrency._simultaneous_start([container(), container()], self.directory)
        self.assertIn((worker.pid, "wait", None), self.events)
        self.assertIn(self.directory, concurrency._UNSETTLED_STARTS)

    def test_result_or_barrier_record_failure_never_clears_fence(self):
        for phase in ("start-barrier", "start-results"):
            with self.subTest(phase=phase):
                self.workers, self.events = [], []
                worker = self.worker()
                def record(directory, value):
                    self.record(directory, value)
                    if value["phase"] == phase:
                        raise OSError("journal full")
                with patch.object(concurrency.subprocess, "Popen", return_value=worker), \
                     patch.object(concurrency, "_record", side_effect=record), \
                     self.assertRaises((OSError, concurrency.UnsettledStarts)):
                    concurrency._simultaneous_start([container()], self.directory)
                self.assertIn((worker.pid, "wait", None), self.events)
                self.assertIn(self.directory, concurrency._UNSETTLED_STARTS)

    def test_failed_actual_reap_retains_fence_and_still_reaps_other_workers(self):
        first, second = self.worker(), self.worker()
        real_wait = first.wait
        def wait(timeout=None):
            if timeout is None:
                raise OSError("wait failed")
            return real_wait(timeout)
        first.wait = wait
        with patch.object(concurrency.subprocess, "Popen", side_effect=[first, second]), \
             patch.object(concurrency, "_record"), self.assertRaises(concurrency.UnsettledStarts):
            concurrency._simultaneous_start([container(), container()], self.directory)
        self.assertIn((second.pid, "wait", None), self.events)
        self.assertIn(self.directory, concurrency._UNSETTLED_STARTS)

    def test_sdk_marker_follows_http_and_reference_version_is_not_borrowed(self):
        for version in ("1.45", "1.55"):
            for failure in (False, True):
                with self.subTest(version=version, failure=failure):
                    output = io.StringIO()
                    def start(identifier):
                        self.assertEqual(output.getvalue(), "ready\n")
                        self.assertEqual(identifier, "owned")
                        if failure:
                            raise OSError("HTTP failed")
                    sdk = SimpleNamespace(api=SimpleNamespace(start=start), close=lambda: None)
                    with patch.object(concurrency.docker, "DockerClient", return_value=sdk) as create, \
                         patch.object(concurrency.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"start\n"))), \
                         patch.object(concurrency.sys, "stdout", output):
                        if failure:
                            with self.assertRaises(OSError):
                                concurrency._owned_start("unix:///owned", version, "owned")
                        else:
                            concurrency._owned_start("unix:///owned", version, "owned")
                    create.assert_called_once_with(base_url="unix:///owned", version=version, timeout=120)
                    self.assertEqual(output.getvalue(), "ready\n" if failure else "ready\nstarted\n")

    def test_real_owned_process_partial_protocol_is_reaped(self):
        original_popen = subprocess.Popen
        children = []
        script = ("import os,sys,time; os.write(1,b'rea'); time.sleep(.02); "
                  "os.write(1,b'dy\\n'); line=sys.stdin.buffer.readline(); "
                  "sys.exit(2) if line != b'start\\n' else None; "
                  "os.write(1,b'star'); time.sleep(.02); os.write(1,b'ted\\n')")
        def spawn(_argv, **kwargs):
            child = original_popen([sys.executable, "-B", "-c", script], **kwargs)
            children.append(child)
            return child
        with patch.object(concurrency.subprocess, "Popen", side_effect=spawn):
            concurrency._simultaneous_start([container(), container()], self.directory)
        self.assertEqual([child.returncode for child in children], [0, 0])
        self.assertNotIn(self.directory, concurrency._UNSETTLED_STARTS)
        for child in children:
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)


class CalibrationTests(unittest.TestCase):
    def test_fixed_budgets_and_unchanged_metadata_algorithms(self):
        self.assertEqual((concurrency.START_SDK_TIMEOUT, concurrency.START_WALL_TIMEOUT,
                          concurrency.SNAPSHOT_HOST_TIMEOUT), (120, 130, 60))
        source = Path(concurrency.__file__).read_text()
        tree = ast.parse(source)
        layer = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_layer")
        self.assertEqual(hashlib.sha256(ast.get_source_segment(source, layer).encode()).hexdigest(),
                         "4a3dd50c2af1c478001af4e419801191b88a2432e9767b06b9b907224e49412d")
        go = (ROOT / "Tests/Compatibility/fixtures/volume-lock.go").read_text()
        self.assertEqual(hashlib.sha256(go[go.index("func snapshot("):go.index("\nfunc run()")].encode()).hexdigest(),
                         "fcd22c9690a7539b900f9016165574b55130da2fa2c5b463372ac4481655f243")
        self.assertIn("client.api.timeout = 45", source)
        self.assertIn("time.monotonic() + 30", source)
        self.assertIn('version="1.45")) as reference:', source)
        self.assertNotIn("from test_volume_corpus import api_deadline", source)
        self.assertEqual(len(concurrency._layer(b"unused")[1]), 265)

    def test_locking_all_backends_uses_sequential_owned_start_and_initialization_same_budget(self):
        class Stop(Exception):
            pass
        for label, shared, daemon in (("reference", True, None), ("block", False, object()),
                                      ("legacy", True, object()), ("managed", True, object())):
            with self.subTest(backend=label):
                peers = [container("first"), container("second")] if shared else [container("first")]
                @contextmanager
                def case(*args):
                    yield Path("unused"), peers, None
                with patch.object(concurrency, "_case", case), \
                     patch.object(concurrency, "_simultaneous_start") as start, \
                     patch.object(concurrency, "_control", return_value={"held": False}), \
                     patch.object(concurrency, "_backend", side_effect=Stop), self.assertRaises(Stop):
                    concurrency._locking(None, daemon, None, label, shared, 0)
                self.assertEqual([c.args[0] for c in start.call_args_list], [[peer] for peer in peers])
                def wait(*, timeout):
                    self.assertEqual(timeout, 60)
                    raise Stop
                peers[0].wait = wait
                with patch.object(concurrency, "_case", case), \
                     patch.object(concurrency, "_simultaneous_start") as start, self.assertRaises(Stop):
                    concurrency._initialization(None, daemon, None, label)
                start.assert_called_once_with(peers, Path("unused"))

    @unittest.skipUnless(shutil.which("go"), "Go compiler required for native fixture regression")
    def test_native_go_watchdog_branches_and_snapshot_readback(self):
        # Calls the unchanged algorithm directly: no /proc, mount, Docker, guest or VM.
        with tempfile.TemporaryDirectory(prefix="concurrency-native-") as temporary:
            work = Path(temporary)
            shutil.copyfile(ROOT / "Tests/Compatibility/fixtures/volume-lock.go", work / "main.go")
            (work / "main_test.go").write_text('''package main
import ("encoding/json"; "os"; "path/filepath"; "testing"; "time")
func TestWatchdog(t *testing.T) {
    for _, op := range []string{"", "request", "try", "mountinfo", "mounts", "unknown"} {
        if watchdogLimit(op) != 20*time.Second { t.Fatalf("%s budget", op) }
    }
    if watchdogLimit("snapshot") != 45*time.Second { t.Fatal("snapshot budget") }
    if watchdogLimit("serve") != 2*time.Hour { t.Fatal("serve budget") }
}
func TestSnapshot(t *testing.T) {
    root := t.TempDir()
    if err := os.WriteFile(filepath.Join(root, "file"), []byte("full readback\\n"), 0600); err != nil { t.Fatal(err) }
    out, err := os.CreateTemp(t.TempDir(), "snapshot")
    if err != nil { t.Fatal(err) }
    defer out.Close()
    previous := os.Stdout
    os.Stdout = out
    defer func() { os.Stdout = previous }()
    if err := snapshot(root); err != nil { t.Fatal(err) }
    if _, err := out.Seek(0, 0); err != nil { t.Fatal(err) }
    var entries map[string]map[string]any
    if err := json.NewDecoder(out).Decode(&entries); err != nil { t.Fatal(err) }
    if len(entries) != 2 || entries["."]["type"] != "directory" || entries["file"]["type"] != "file" { t.Fatal(entries) }
    if entries["file"]["mode"] != float64(0600) || entries["file"]["uid"] != float64(os.Getuid()) || entries["file"]["gid"] != float64(os.Getgid()) { t.Fatal(entries) }
    if entries["file"]["sha256"] != "'''+hashlib.sha256(b"full readback\n").hexdigest()+'''" { t.Fatal(entries) }
}
''')
            environment = {k: v for k, v in os.environ.items() if k not in ("GOOS", "GOARCH")}
            environment.update(CGO_ENABLED="0", GOWORK="off", GO111MODULE="off")
            result = subprocess.run(["go", "test", "-count=1", "-v", "main.go", "main_test.go"],
                                    cwd=work, env=environment, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("--- PASS: TestWatchdog", result.stdout)
            self.assertIn("--- PASS: TestSnapshot", result.stdout)


if __name__ == "__main__":
    unittest.main()
