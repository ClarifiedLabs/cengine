#!/usr/bin/env python3
"""Host-only stream and real child-join regressions. No Docker/helper execution."""
from pathlib import Path
import sys
import json
import os
import subprocess
import tempfile
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_retained_reader as r


def frame(raw, channel=1):
    return struct.pack(">BxxxI", channel, len(raw)) + raw


READY = b'{"ready":true,"readerPID":17}\n'


def joined(snapshot):
    return json.dumps(dict(version=1, readerPID=17, exitCode=0, snapshot=snapshot)).encode() + b'\n'


class Socket:
    def __init__(self, raw): self.raw, self.sent, self.closed = bytearray(raw), [], False
    def recv(self, n):
        n = min(n, 3)
        value = bytes(self.raw[:n]); del self.raw[:n]; return value
    def sendall(self, raw): self.sent.append(raw)
    def settimeout(self, value): assert 0 < value <= 10
    def close(self): self.closed = True


class API:
    def __init__(self, raw, status=None):
        self.sock, self.calls = Socket(raw), []
        self.status = status or dict(Running=False, ExitCode=0)
    def exec_create(self, owner, command, **kwargs):
        self.calls.append((owner, command, kwargs)); return dict(Id="owned")
    def exec_start(self, identifier, **kwargs): self.calls.append(identifier); return self.sock
    def exec_inspect(self, identifier): raise AssertionError("fenced API status is not a guest child join")


class ReaderTests(unittest.TestCase):
    def start(self, raw, status=None):
        api = API(raw, status)
        return api, r.RetainedReader(api, SimpleNamespace(id="peer"), lambda: 10)

    def test_prestart_then_one_owned_trigger_and_successful_join(self):
        api, reader = self.start(frame(READY) + frame(joined(dict(snapshot="actual"))))
        self.assertEqual(len(api.calls), 2); self.assertEqual(api.sock.sent, [])
        self.assertEqual(reader.snapshot(), dict(snapshot="actual"))
        self.assertEqual(api.sock.sent, [b'\x01']); self.assertTrue(api.sock.closed)
        self.assertEqual(len(api.calls), 2)
        with self.assertRaises(ValueError): reader.snapshot()

    def test_ready_is_strict_and_failure_closes_stream(self):
        for raw in (b'{"ready":1,"readerPID":17}\n', b'{"ready":false,"readerPID":17}\n',
                    b'{"ready":true}\n', b'{"ready":true,"readerPID":true}\n',
                    b'{"ready":true,"readerPID":0}\n', b'{"ready":true,"readerPID":17,"extra":1}\n', READY + b'{}\n'):
            api = API(frame(raw))
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                r.RetainedReader(api, SimpleNamespace(id="peer"), lambda: 10)
            self.assertTrue(api.sock.closed)

    def test_malformed_frames_stderr_truncation_extra_output_fail(self):
        for bad in (frame(b'error\n', 2), b'\x01', frame(b'{}\n')[:-1], frame(b'{}\n{}\n'),
                    struct.pack('>BxxxI', 1, 131065), b'\x01\x01\0\0\0\0\0\x03{}\n'):
            api, reader = self.start(frame(READY) + bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError): reader.snapshot()
            self.assertTrue(api.sock.closed)

    def test_eof_is_not_join_and_invalid_child_receipt_cannot_ack(self):
        good = dict(version=1, readerPID=17, exitCode=0, snapshot={})
        invalid = [{}, dict(snapshot={})]
        for key in good:
            invalid.append({k: v for k, v in good.items() if k != key})
        invalid += [{**good, **change} for change in (
            dict(version=True), dict(version=2), dict(readerPID=18), dict(readerPID=True),
            dict(exitCode=137), dict(exitCode=1), dict(exitCode=False), dict(exitCode=None),
            dict(snapshot=None), dict(unknown=True))]
        for receipt in invalid:
            api, reader = self.start(frame(READY) + frame(json.dumps(receipt).encode() + b'\n'))
            with self.subTest(receipt=receipt), self.assertRaises(ValueError): reader.snapshot()
            self.assertTrue(api.sock.closed)

    def test_only_actual_child_join_not_parent_api_fence_controls_baseline(self):
        # The parent exec is fenced at 137. The source-pinned supervisor joined
        # its prestarted child at 0; this is a different process fact, not a waiver.
        api, reader = self.start(frame(READY) + frame(joined(dict(actual=True))),
            dict(Running=False, ExitCode=137))
        self.assertEqual(reader.snapshot(), dict(actual=True))
        self.assertEqual(len(api.calls), 2)

    def test_absolute_deadline_never_renews(self):
        with patch.object(r.time, 'monotonic', return_value=100):
            api, reader = self.start(frame(READY) + frame(joined({})))
        with patch.object(r.time, 'monotonic', return_value=110), self.assertRaises(ValueError): reader.snapshot()
        self.assertEqual(api.sock.sent, []); self.assertTrue(api.sock.closed)


class GuestSupervisorTests(unittest.TestCase):
    def test_actual_supervisor_joins_real_children_before_emitting_result(self):
        source = (ROOT / "Tests/Compatibility/fixtures/managed-prepare-faults.go").read_text()
        body = source[source.index("func superviseReader("):source.index("func retainedWait(")]
        with tempfile.TemporaryDirectory(prefix="cengine-reader-test-") as work:
            path = Path(work)
            (path / "reader.go").write_text('package reader\nimport ("bufio"; "bytes"; "encoding/json"; "errors"; "io"; "os/exec")\n' + body)
            (path / "reader_test.go").write_text((ROOT / "tools/tests/fixtures/rtm103-reader-supervisor.gotxt").read_text())
            env = {**os.environ, "GO111MODULE": "off", "GOWORK": "off", "GOFLAGS": "", "GOTOOLCHAIN": "local"}
            subprocess.run(["go", "test", "-count=1", "-timeout=20s", "."], cwd=path, env=env, check=True, timeout=40)


class SourceOrderingTests(unittest.TestCase):
    def test_prestart_and_durable_independent_baseline_precede_begin(self):
        source = (ROOT / "Tests/Compatibility/managed_stale_consumer.py").read_text()
        self.assertLess(source.index("reader = (root_backing.RootBackingReader if root_case else RetainedReader)("), source.index('queue.publish("original-consumer.capture.json"'))
        self.assertLess(source.index('wait_artifact(".original-consumer.armed.json")'), source.index("reader.snapshot()"))
        self.assertLess(source.index('record("original-consumer-independent-baseline"'), source.index('queue.publish(request_id + ".original-consumer.baseline.json"'))
        self.assertLess(source.index('wait_artifact(".original-consumer.baseline-accepted.json")'), source.index('wait_artifact(".original-consumer.begun.json")'))
        self.assertLess(source.index("backing.fresh_retained_snapshot("), source.index("backing.fresh_retained_write("))

    def test_probe_starts_child_before_ready_and_keeps_one_watchdog(self):
        source = (ROOT / "Tests/Compatibility/fixtures/managed-prepare-faults.go").read_text()
        supervisor = source[source.index("func superviseReader("):source.index("func retainedWait(")]
        self.assertLess(supervisor.index("child.Start()"), supervisor.index("reader.ReadSlice("))
        self.assertLess(supervisor.index("reader.ReadSlice("), supervisor.index("json.NewEncoder(output)"))
        self.assertLess(supervisor.index("err = child.Wait()"), supervisor.index("Snapshot json.RawMessage"))
        wrapper = source[source.index("func retainedWait("):source.index("func retainedWaitChild(")]
        self.assertEqual(wrapper.count("time.AfterFunc(10*time.Second"), 1)
        self.assertLess(wrapper.index("time.AfterFunc("), wrapper.index("superviseReader("))

    def test_swift_deadline_and_admission_are_not_reopened_for_reader(self):
        source = (ROOT / "Sources/CEngineRuntime/RawVirtualizationBackend.swift").read_text()
        start = source.index("private func prepareOriginalConsumerObservation(")
        body = source[start:source.index("public func validateManagedStorageReplacement", start)]
        self.assertLess(body.index("serviceWork.close()"), body.index("armOriginalRuntime("))
        self.assertLess(body.index("validateOriginalBaseline(baseline)"), body.index("recordBackingBaseline(baseline)"))
        self.assertLess(body.index("recordBackingBaseline(baseline)"), body.index("phase: .baselineAccepted"))
        self.assertNotIn("reopen", body)
        self.assertNotIn("prepareExec", body)
        self.assertIn("deadline.remaining()", body)


if __name__ == '__main__': unittest.main()
