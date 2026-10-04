#!/usr/bin/env python3
"""Stdlib v2 original-consumer oracle fixtures; never native acceptance."""
import ast
import base64
import copy
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_original_lifecycle_evidence as e
import managed_stale_consumer as s
p = s.p
WORKER = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-worker-lifecycle-evidence.py"))
ORIGINAL = runpy.run_path(str(ROOT / "tools/tests/test-managed-stale-consumer.py"))
FRESH = runpy.run_path(str(ROOT / "tools/tests/test-managed-fresh-getattr.py"))


def peer_fixture(byte):
    # DER-shaped comparison fixture only, not a signed/authenticated certificate.
    def der(tag, content): return bytes([tag, len(content)]) + content
    spki = der(48, der(48, der(6, b"\x2b\x65\x70")) + der(3, b"\0" + byte * 32))
    tbs = der(48, der(2, b"\1") + der(48, b"") * 4 + spki)
    certificate = der(48, tbs + der(48, b"") + der(3, b"\0"))
    encoded = lambda value: base64.b64encode(value).decode()
    return dict(tlsRootDER=encoded(b"public-root-" + byte), serverDER=encoded(certificate),
        serverKey=p.digest(spki), dataAddress="192.0.2.1:1234")


def fixture():
    args, _, _, _ = WORKER["fixture"]()
    peers = [peer_fixture(b"a"), peer_fixture(b"b")]
    epochs = [record["checkpoint"]["currentContext"]["serviceEpoch"] for record in args[:2]]
    def pins(value):
        if isinstance(value, dict):
            if set(value) == {"identity", "service_epoch", "tls_root_sha256", "server_spki", "bootstrap_key"}:
                peer = peers[epochs.index(value["service_epoch"])]
                value.update(tls_root_sha256=p.digest(base64.b64decode(peer["tlsRootDER"])), server_spki=peer["serverKey"])
            for child in value.values(): pins(child)
        elif isinstance(value, list):
            for child in value: pins(child)
    for record in args[:2]: pins(record)
    return args, peers


def substitute(value, mapping):
    if isinstance(value, dict): return {mapping.get(k, k): substitute(v, mapping) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [substitute(v, mapping) for v in value]
    return mapping.get(value, value) if isinstance(value, str) else value


def consumer_fixture(case):
    args, peers = fixture()
    values = list(ORIGINAL["values"](case))
    index = 0 if s.observes_predecessor(case) else 1
    _, projection = e.owner(args[index])
    comparison = e.comparison(projection, peers[index])
    ready, wanted = values[3]["ready"], comparison["ready"]
    mapping = {ready[k]: wanted[k] for k in ("storeUUID", "serviceEpoch", "workerUUID", "controllerKey")}
    mapping[values[2]["serviceEpoch"]] = args[0]["checkpoint"]["currentContext"]["serviceEpoch"]
    for key in ("serverDER", "tlsRootDER", "serverKey"):
        if key in ready: mapping[ready[key]] = wanted[key]
    mapping[p.digest(base64.b64decode(ready["serverDER"]))] = p.digest(base64.b64decode(wanted["serverDER"]))
    if case == "wrong-epoch":
        original_epoch = values[0]["original"]["hello"]["epoch"]
        epoch = wanted["serviceEpoch"]
        mapping[original_epoch] = ("1" if epoch[0] == "0" else "0") + epoch[1:]
    values = substitute(values, mapping)
    values[3] = comparison
    return args, values


class OriginalLifecycleTests(unittest.TestCase):
    def test_all_fifteen_use_original_oracles_not_prepare_receipts(self):
        for case in s.IMPLEMENTED_CASES:
            with self.subTest(case=case), patch.object(e.worker, "replacement_proof", side_effect=AssertionError("PREPARE oracle called")):
                args, values = consumer_fixture(case)
                e.replacement_proof(*args)
                self.assertEqual(s.correlated_result(*values), values[0])
                self.assertEqual(values[3]["format"], e.VERSION)
                for key in ("boot", "transitions", "workerReplacements", "binding"):
                    self.assertNotIn(key, values[3])

    def test_original_denials_are_still_distinct(self):
        for case in s.IMPLEMENTED_CASES:
            _, values = consumer_fixture(case)
            bad = copy.deepcopy(values)
            bad[0]["original"]["originalOperation"]["errorClass"] = "eof"
            with self.subTest(case=case), self.assertRaises(ValueError): s.correlated_result(*bad)
        for case in (*s.HELLO_CASES, s.IMPLEMENTED, "same-e-existing-data", "same-e-retained-fd", *s.REGISTRATION_CASES):
            _, values = consumer_fixture(case)
            values[0]["worker"]["evidence"]["stage"] = "prehello-no-credential"
            with self.subTest(case=case), self.assertRaises(ValueError): s.correlated_result(*values)
        for case in (*s.SAME_E_CASES, *s.REGISTRATION_CASES, "same-e-retained-fd"):
            _, values = consumer_fixture(case)
            values[0]["retirement"]["receipt"]["revision"] = 0
            with self.subTest(case=case), self.assertRaises(ValueError): s.correlated_result(*values)

    def test_mutated_root_service_physical_receipt_and_census_rejected(self):
        mutations = [
            (1, ("manifest", "bytes"), 8192),
            (1, ("checkpoint", "nativeReplacementAttempted"), False),
            (1, ("checkpoint", "latestServiceChange", "operationID"), WORKER["uid"]()),
            (1, ("checkpoint", "currentContext", "controllerKey"), "9" * 64),
            (1, ("checkpoint", "latestServiceRequest", "predecessorWorkerUUID"), WORKER["uid"]()),
            (1, ("checkpoint", "references"), []),
            (1, ("checkpoint", "serviceLinks"), []),
            (2, ("counter",), True), (2, ("counter",), 2),
            (3, ("containedContainerIDs",), ["a" * 64]),
            (3, ("ownerRequest", "nowUnixSeconds"), 90),
            (5, ("reconciliationRequired",), True),
        ]
        for index, path, value in mutations:
            args, _ = fixture(); args = copy.deepcopy(args)
            target = args[index]
            for part in path[:-1]: target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises((ValueError, KeyError)): e.replacement_proof(*args)
        for field in ("tls_root_sha256", "server_spki"):
            args, _ = fixture()
            args[1]["checkpoint"]["currentService"]["boot"][field] = args[0]["checkpoint"]["currentService"]["boot"][field]
            with self.subTest(field=field), self.assertRaises(ValueError): e.replacement_proof(*args)

    def test_explicit_reads_and_missing_live_peer_fail_closed(self):
        args, peers = fixture()
        for record, peer in zip(args[:2], peers):
            reader = Mock(side_effect=[(record["checkpoint"], "a" * 64), (record["manifest"], "b" * 64)])
            actual, stamp = e.read_owner(Path("/owned"), reader)
            self.assertEqual(actual, record); self.assertEqual(len(stamp), 64)
            _, projection = e.owner(actual)
            for missing in (None, {}):
                with self.assertRaises(ValueError): e.peer_comparison(projection, missing)
            self.assertEqual(e.peer_comparison(projection, lambda _: peer), e.comparison(projection, peer))
            for field in ("tlsRootDER", "serverDER", "serverKey"):
                bad = dict(peer); bad[field] = peers[1 if peer == peers[0] else 0][field]
                with self.subTest(field=field), self.assertRaises(ValueError): e.comparison(projection, bad)
        for version in (None, "storage-lifecycle.v1", "storage-lifecycle.v3"):
            with self.assertRaises(ValueError): e.read_owner(Path("/owned"), Mock(return_value=({"version": version}, "a" * 64)))

    def test_fresh_data_requires_actual_successor_wire_reply(self):
        for case in s.FRESH_GETATTR_CASES:
            args, peers = fixture()
            values = list(FRESH["fixture"](case))
            _, projection = e.owner(args[1])
            comparison = e.comparison(projection, peers[1])
            ready, wanted = values[3]["ready"], comparison["ready"]
            mapping = {ready[k]: wanted[k] for k in ("storeUUID", "serviceEpoch", "workerUUID", "controllerKey")}
            mapping[values[1]["scope"]["serviceEpoch"]] = args[0]["checkpoint"]["currentContext"]["serviceEpoch"]
            mapping[p.digest(base64.b64decode(ready["serverDER"]))] = p.digest(base64.b64decode(wanted["serverDER"]))
            values = substitute(values, mapping); values[3] = comparison
            with self.subTest(case=case): self.assertEqual(s.fresh_getattr(*values), values[0])
            for field, value in (("serverDERSHA256", "0" * 64), ("released", False)):
                bad = copy.deepcopy(values); bad[0][field] = value
                with self.subTest(case=case, field=field), self.assertRaises(ValueError): s.fresh_getattr(*bad)
            bad = copy.deepcopy(values)
            bad[0]["evidence"]["originalOperation"]["errorClass"] = "transport-failed"
            with self.assertRaises(ValueError): s.fresh_getattr(*bad)

    def test_three_versioned_reads_keep_native_containment_cleanup_and_queue(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/managed_stale_consumer.py").read_text())
        live = next(node for node in tree.body if getattr(node, "name", "") == "run_live")
        calls = [ast.unparse(node.func) for node in ast.walk(live) if isinstance(node, ast.Call)]
        self.assertEqual(calls.count("lifecycle.read_owner"), 3)
        self.assertEqual(calls.count("lifecycle.replacement_proof"), 1)
        self.assertEqual(calls.count("lifecycle.peer_comparison"), 2)
        self.assertNotIn("recovery.worker_owner", calls)
        self.assertNotIn("recovery.read_public", calls)
        for name in ("wait_exit", "surviving_hosts", "containment_inventory", "fresh_getattr", "fresh_read",
                "fixture_receipts", "backing.fresh_retained_write", "recovery.settled_worker_artifacts"):
            self.assertIn(name, calls)
        self.assertEqual(calls.count("storage_target"), 2)
        self.assertEqual(calls.count("recovery.settled_worker_artifacts"), 2)
        self.assertIs(s.storage_target, WORKER["worker"].storage_target)


if __name__ == "__main__": unittest.main()
