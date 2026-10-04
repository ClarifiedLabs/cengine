#!/usr/bin/env python3
"""Engine-free oracle negatives, not RTM103 native acceptance."""
import ast
import base64
import copy
import runpy
from pathlib import Path
import sys
from types import SimpleNamespace
import io
import tarfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_stale_consumer as s
import managed_prepare_faults as p


def values(case=s.IMPLEMENTED):
    if case in s.REGISTRATION_CASES:
        fixture = runpy.run_path(str(ROOT / "tools/tests/test-managed-registration-projection.py"))["fixture"]
        return fixture(case)
    if case in s.root_backing.ROOT_CASES:
        fixture = runpy.run_path(str(ROOT / 'tools/tests/test-managed-root-projection.py'))['fixture']
        return fixture(case == s.root_backing.ROOT_CASES[1])
    if case in s.backing.FD_CASES:
        fixture = runpy.run_path(str(ROOT / 'tools/tests/test-managed-retained-projection.py'))['fixture']
        return fixture(case == s.backing.FD_CASES[0])
    uid = lambda: str(uuid.uuid4())
    scope = dict(intent=uid(), store=uid(), serviceEpoch=uid(), controllerEpoch=1, controllerKey="c" * 64,
        container="d" * 64, containerInstance=uid(), launch=uid(), prepare=uid(), specificationDigest="e" * 64)
    slot = dict(volume=uid(), attachment=uid(), role="runtime", mode="read-only" if case == "wrong-mode" else "read-write", key="f" * 64)
    intent = {("id" if k == "intent" else k): v for k, v in scope.items()}
    intent["slots"] = [slot]
    version = 3 if case == "cross-e-existing-data" else 1
    b = dict(version=version, profile=p.FULL_PROFILE, requestID=uid(), armDigest="a" * 64, operationUUID=uid(), caseName=case,
        generation=4, boot=dict(shimLaunchUUID=scope["launch"], guestBootNonce=uid()), scope=scope,
        targetAttachment=slot["attachment"], key=slot["key"], certificateSHA256="b" * 64)
    ready = dict(storeUUID=scope["store"], serviceEpoch=uid(), workerUUID=uid(), controllerEpoch=1,
        controllerKey=scope["controllerKey"], serverDER=base64.b64encode(b"public-test-DER").decode())
    runtime = dict(store=scope["store"], volume=slot["volume"], attachment=slot["attachment"], container=scope["container"],
        launch=scope["launch"], key=slot["key"], role=slot["role"], mode=slot["mode"])
    q = dict(version=3, profile=p.FULL_PROFILE, requestID=b["requestID"], armDigest=b["armDigest"], operationUUID=b["operationUUID"],
        caseName=s.IMPLEMENTED, originalBootBinding=b["boot"], original=dict(epoch=scope["serviceEpoch"], binding=runtime),
        originalLeafSHA256=b["certificateSHA256"], workerScope={k: ready[k] for k in ("storeUUID", "serviceEpoch", "workerUUID")})
    e = dict(stage="tls-client-certificate", errorClass="unknown-authority", storeUUID=scope["store"], serviceEpoch=ready["serviceEpoch"],
        rejectedLeafSHA256=b["certificateSHA256"], byteCount=200, prefixSHA256="a" * 64)
    arm = dict(version=version, profile=p.FULL_PROFILE, requestID=b["requestID"], operationUUID=b["operationUUID"], caseName=case,
        binding=b["boot"], scope=scope, targetAttachment=slot["attachment"], leafSHA256=b["certificateSHA256"])
    original = dict(arm=arm, stage="original-owner-prefix-correlated", scope={**scope, **{k: ready[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")}},
        keySHA256=b["key"], mountIdentitySHA256="1" * 64, serverDERSHA256=p.digest(b"public-test-DER"), signCount=1,
        signInputSHA256="2" * 64, bytesWrittenAfterSign=100, clientWrittenBytes=250, clientPrefixBytes=200, clientPrefixSHA256=e["prefixSHA256"],
        localError="eof", fdOperation="fsync-directory", fdSequence=2 if case == "cross-e-retained-fd" else 1,
        originalOperation=(dict(kind="data-getattr-root", sequence=2, errorClass="client-closed-joined") if case == "cross-e-existing-data"
            else dict(kind="fsync-directory", sequence=2, errorClass="eio") if case == "cross-e-retained-fd"
            else dict(kind="", sequence=0, errorClass="")))
    if case in s.HELLO_CASES:
        name = s.wire_case(case)
        b.update(version=2, caseName=name)
        ready["serviceEpoch"] = scope["serviceEpoch"]
        q.update(version=4, caseName=name)
        q["workerScope"]["serviceEpoch"] = scope["serviceEpoch"]
        arm.update(version=2, caseName=name)
        original["scope"] = dict(scope)
        original["originalOperation"] = dict(kind="data-wrong-hello", sequence=1, errorClass="peer-closed-before-root")
        prepare = dict(volume=slot["volume"], attachment=uid(), role="prepare", mode="read-write", key="9" * 64)
        intent["slots"].append(prepare)
        hello = dict(epoch=scope["serviceEpoch"], binding=dict(runtime))
        if case == "wrong-volume":
            slot["attachment"] = "00000000-0000-4000-8000-000000000001"
            runtime["attachment"] = slot["attachment"]
            b["targetAttachment"] = slot["attachment"]
            arm["targetAttachment"] = slot["attachment"]
            other = dict(volume=uid(), attachment="ffffffff-ffff-4fff-bfff-ffffffffffff", role="runtime", mode="read-write", key="8" * 64)
            intent["slots"].append(other)
            hello["binding"]["attachment"] = slot["attachment"]
            hello["binding"]["volume"] = other["volume"]
        elif case == "wrong-mode": hello["binding"]["mode"] = "read-write"
        elif case == "wrong-key": hello["binding"]["key"] = prepare["key"]
        elif case == "wrong-role": hello["binding"].update(role="prepare", prepare=scope["prepare"])
        else: hello["epoch"] = ("1" if scope["serviceEpoch"][0] == "0" else "0") + scope["serviceEpoch"][1:]
        original["hello"] = copy.deepcopy(hello)
        e.update(stage="pki-verify-peer", errorClass="unauthorized", serviceEpoch=scope["serviceEpoch"], hello=hello)
    value = dict(worker=dict(query=q, state="finalized", selectedCount=1, evidence=e), original=original)
    if case in s.SAME_E_CASES:
        b.update(version=4); arm.update(version=4)
        ready["serviceEpoch"] = scope["serviceEpoch"]
        q.update(version=6 if case == s.SAME_E_CASES[0] else 5, caseName=case)
        q["workerScope"]["serviceEpoch"] = scope["serviceEpoch"]
        slot["retireOperation"] = uid()
        receipt = dict(schema=3, store=scope["store"], volume=slot["volume"],
                       attachment=slot["attachment"], launch=runtime["launch"], revision=20)
        value["retirement"] = dict(operation=slot["retireOperation"], receipt=receipt, queryRevision=20,
            epoch=scope["serviceEpoch"], controller=dict(epoch=scope["controllerEpoch"], key=scope["controllerKey"]),
            attachment=dict(binding=copy.deepcopy(runtime), phase="DRAINED", receipt=copy.deepcopy(receipt), retirement=slot["retireOperation"]))
        original.update(scope=dict(scope), rootRequest=dict(node=19, requestSequence=5),
            clientPrefixBytes=0, clientPrefixSHA256="")
        e.clear(); e.update(stage="request-admit" if case == s.SAME_E_CASES[0] else "authenticate-data",
            errorClass="blocked", storeUUID=scope["store"], serviceEpoch=scope["serviceEpoch"], rejectedLeafSHA256=b["certificateSHA256"])
        if case == s.SAME_E_CASES[0]:
            original.update(stage="original-data-attempt", signCount=0, signInputSHA256="", bytesWrittenAfterSign=0,
                clientWrittenBytes=0, localError="", originalOperation=dict(kind="data-getattr-root", sequence=2, errorClass="transport-failed"))
            e["admission"] = dict(original=copy.deepcopy(q["original"]), requestSequence=5,
                operation="get_attr", node=19, authKind=3, noHandle=True)
        else:
            original.update(stage="original-owner-signed-flight", hello=copy.deepcopy(q["original"]),
                originalOperation=dict(kind="data-original-hello", sequence=2, errorClass="peer-closed-before-root"))
            e["hello"] = copy.deepcopy(q["original"])
    return value, b, intent, dict(ready=ready)


class ClosedSelection(unittest.TestCase):
    def test_full_inventory_and_only_implemented_case(self):
        self.assertEqual(len(s.CASES), 18)
        self.assertEqual(s.IMPLEMENTED_CASES, ("cross-e-existing-data", "cross-e-old-leaf-reconnect",
            "wrong-volume", "wrong-key", "wrong-role", "wrong-mode", "wrong-epoch",
            "same-e-existing-data", "same-e-old-leaf-reconnect", "same-e-retained-fd", "cross-e-retained-fd",
            "cross-mount-root-grant", "retired-root-grant-replay", "attachment-key-reuse", "delayed-registration"))
        for case in s.CASES:
            if case in s.IMPLEMENTED_CASES:
                report = s.selection(p.FULL_PROFILE, s.CASES, case)
                self.assertFalse(report["fullAcceptance"])
                self.assertEqual(len(report["missing"]), 17)
            else:
                with self.assertRaises(ValueError): s.selection(p.FULL_PROFILE, s.CASES, case)
        with self.assertRaises(ValueError): s.selection(p.FULL_PROFILE, (s.IMPLEMENTED,), s.IMPLEMENTED)

    def test_wrapper_dispatches_only_complete_catalog_and_implemented_case(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        wrapper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_original_consumer_shard")
        calls = []
        namespace = dict(_run_prepare_case=lambda *a, **k: calls.append((a, k)))
        exec(compile(ast.Module(body=[wrapper], type_ignores=[]), "actual-original-wrapper", "exec"), namespace)
        run = namespace["run_original_consumer_shard"]
        args = dict(probe="probe", probe_sha256="a" * 64, source_sha256="b" * 64, expected_commit="commit", evidence="external")
        for profile, cases, case in ((p.PROFILE, s.CASES, s.IMPLEMENTED),
                                     (p.FULL_PROFILE, (s.IMPLEMENTED,), s.IMPLEMENTED),
                                     (p.FULL_PROFILE, s.CASES, "replayed-takeover")):
            with self.assertRaises(ValueError): run(None, profile=profile, cases=cases, case=case, **args)
        self.assertFalse(calls)
        for case in set(s.CASES) - set(s.IMPLEMENTED_CASES):
            with self.assertRaises(ValueError): run(None, profile=p.FULL_PROFILE, cases=s.CASES, case=case, **args)
        self.assertFalse(calls)
        for case in s.IMPLEMENTED_CASES:
            run("owned-daemon", profile=p.FULL_PROFILE, cases=s.CASES, case=case, **args)
            positional, dispatched = calls[-1]
            self.assertEqual(positional, ("owned-daemon",))
            self.assertEqual(dispatched, dict(**args, profile=p.FULL_PROFILE,
                staged=s.selection(p.FULL_PROFILE, s.CASES, case), fault_case="normal",
                early=True, full=True, original_consumer_case=case))
            self.assertFalse(dispatched["staged"]["fullAcceptance"])
        self.assertEqual(len(calls), 15)

    def test_source_reuses_live_normal_before_unlink_or_stop(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        runner = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_prepare_case")
        text = ast.get_source_segment((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text(), runner)
        self.assertLess(text.index("baseline = observe(\"root-snapshot\" if root_case else \"snapshot\")"), text.index("return run_live("))
        self.assertLess(text.index("return run_live("), text.index("observe(\"empty\")"))


class IndependentWriterTests(unittest.TestCase):
    def test_matches_volume_despite_reversed_attachment_order(self):
        for case in (*s.root_backing.ROOT_CASES, "writer"):
            original = dict(volume="00000000-0000-4000-8000-000000000001",
                attachment="00000000-0000-4000-8000-000000000002", key="a" * 64)
            target = dict(original, role="runtime", mode="read-write", key="b" * 64,
                attachment="ffffffff-ffff-4fff-bfff-ffffffffffff")
            other = dict(target, volume="00000000-0000-4000-8000-000000000003",
                attachment="00000000-0000-4000-8000-000000000004", key="c" * 64)
            slots = [target, other] if case in s.root_backing.ROOT_CASES else [target]
            for ordered in (slots, list(reversed(slots))):
                with self.subTest(case=case, ordered=ordered):
                    self.assertIs(s.independent_writer_slot(dict(slots=ordered), case, original), target)
            for changes in (dict(volume=str(uuid.uuid4())), dict(mode="read-only"),
                            dict(key=original["key"]), dict(attachment=original["attachment"]),
                            dict(receipt={})):
                changed = copy.deepcopy(slots); changed[0].update(changes)
                with self.subTest(case=case, changes=changes), self.assertRaises(ValueError):
                    s.independent_writer_slot(dict(slots=changed), case, original)


class CandidateNegatives(unittest.TestCase):
    def test_actual_carrier_uses_owner_derived_slot_and_generation(self):
        _, binding, intent, _ = values()
        intent.update(phase="running")
        request = dict(version=1, profile=p.FULL_PROFILE, requestID=binding["requestID"],
            operationUUID=binding["operationUUID"], caseName=s.IMPLEMENTED,
            container=intent["container"], containerInstance=intent["containerInstance"])
        replacement = dict(operationUUID=binding["operationUUID"], predecessor=dict(serviceEpoch=intent["serviceEpoch"], workerUUID=str(uuid.uuid4())), store=intent["store"])
        offered = dict(request=request, binding=binding, ownerRequest={k: v for k,v in replacement.items() if k != "store"})
        offered["ownerRequest"]["nowUnixSeconds"] = 123
        self.assertEqual(s.candidate(offered, request, replacement, intent, 4), binding)
        for mutate in (lambda x: x["binding"].update(generation=5),
                       lambda x: x["ownerRequest"].update(operationUUID=str(uuid.uuid4())),
                       lambda x: x["binding"].update(targetAttachment=str(uuid.uuid4()))):
            changed = copy.deepcopy(offered); mutate(changed)
            with self.assertRaises((ValueError, StopIteration)):
                s.candidate(changed, request, replacement, intent, 4)

    def test_candidate_original_version_is_exact_for_all_fifteen_selectors(self):
        for case in s.IMPLEMENTED_CASES:
            _, binding, intent, _ = values(case)[:4]
            request = dict(version=1, profile=p.FULL_PROFILE, requestID=binding["requestID"],
                operationUUID=binding["operationUUID"], caseName=s.wire_case(case),
                container=intent["container"], containerInstance=intent["containerInstance"])
            replacement = dict(operationUUID=binding["operationUUID"],
                predecessor=dict(serviceEpoch=intent["serviceEpoch"], workerUUID=str(uuid.uuid4())))
            offered = dict(request=request, binding=binding, ownerRequest=dict(**replacement, nowUnixSeconds=123))
            self.assertEqual(s.candidate(offered, request, replacement, intent, 4), binding)
            expected = 6 if case in s.root_backing.ROOT_CASES else 7 if case == s.backing.FD_CASES[0] else 5 if case in s.backing.FD_CASES else 4 if case in (*s.SAME_E_CASES, *s.REGISTRATION_CASES) else 3 if case == "cross-e-existing-data" else 2 if case.startswith("wrong-") else 1
            self.assertEqual(binding["version"], expected)
            for version in (True, float(expected), *(v for v in (1, 2, 3, 4, 5, 6, 7, 8) if v != expected)):
                changed = copy.deepcopy(offered); changed["binding"]["version"] = version
                with self.assertRaises(ValueError): s.candidate(changed, request, replacement, intent, 4)


class CorrelationNegatives(unittest.TestCase):
    def test_closed_projection_is_not_native_proof(self):
        args = values()
        self.assertEqual(s.correlated_result(*args), args[0])

    def test_cross_e_original_operations_are_exact_and_independent_of_tls(self):
        for case in (s.IMPLEMENTED, "cross-e-existing-data"):
            args = values(case)
            self.assertEqual(s.correlated_result(*args), args[0])
            for mutate in (
                lambda v: v["original"].pop("originalOperation"),
                lambda v: v["original"]["originalOperation"].update(sequence=True),
                lambda v: v["original"]["originalOperation"].update(errorClass="eof"),
                lambda v: v["original"]["originalOperation"].update(privateKey="forbidden"),
                lambda v: v["worker"]["evidence"].update(errorClass="client-closed-joined"),
                lambda v: v["original"]["arm"].update(caseName="same-e-existing-data"),
            ):
                changed = copy.deepcopy(args); mutate(changed[0])
                with self.assertRaises((ValueError, KeyError)): s.correlated_result(*changed)
        for case in ("cross-e-existing-data",):
            args = values(case)
            args[0]["original"]["originalOperation"] = dict(kind="", sequence=0, errorClass="")
            with self.assertRaises(ValueError): s.correlated_result(*args)
        args = values("cross-e-retained-fd")
        args[0]["original"]["fdSequence"] = 1
        with self.assertRaises(ValueError): s.correlated_result(*args)

    def test_cross_e_data_v3_requires_second_negative_not_legacy_or_missing_positive(self):
        args = values("cross-e-existing-data")
        self.assertEqual(args[1]["version"], 3)
        self.assertEqual(args[0]["worker"]["query"]["version"], 3)  # Worker unchanged.
        self.assertEqual(s.correlated_result(*args), args[0])
        legacy = copy.deepcopy(args)
        legacy[1]["version"] = legacy[0]["original"]["arm"]["version"] = 1
        legacy[0]["original"]["originalOperation"]["sequence"] = 1
        with self.assertRaises(ValueError): s.correlated_result(*legacy)
        for mutation in (
            lambda x: x[1].update(version=1),
            lambda x: x[0]["original"]["arm"].update(version=1),
            lambda x: x[0]["original"]["originalOperation"].update(sequence=1),
            lambda x: x[0]["original"]["originalOperation"].update(kind="", sequence=0, errorClass=""),
            lambda x: x[0]["original"]["originalOperation"].update(sequence=1, errorClass="ok"),
            lambda x: x[0]["original"].pop("originalOperation"),
            lambda x: x[0]["original"].update(positive=dict(kind="data-getattr-root", sequence=1, errorClass="ok")),
            lambda x: x[0]["worker"]["query"].update(version=4),
        ):
            changed = copy.deepcopy(args); mutation(changed)
            with self.assertRaises((ValueError, KeyError)): s.correlated_result(*changed)
        # No encoded Python positive can replace Swift's actual v3 Arm/Begin
        # validation. Old v1/negative-1 proves no preceding successful GetAttr.
        for case in s.IMPLEMENTED_CASES:
            args = values(case)
            self.assertEqual(s.correlated_result(*args), args[0])
            for index in (0, 1):
                changed = copy.deepcopy(args)
                if index == 0: changed[0]["original"]["arm"]["version"] = float(changed[1]["version"])
                else: changed[1]["version"] = float(changed[1]["version"])
                with self.assertRaises(ValueError): s.correlated_result(*changed)

    def test_issued_hello_requires_exact_original_current_worker_and_real_alternate(self):
        for case in s.HELLO_CASES:
            args = values(case)
            self.assertEqual(s.correlated_result(*args), args[0])
            for mutate in (
                lambda x: x[0]["worker"].update(state="observed"),
                lambda x: x[0]["worker"]["evidence"].update(errorClass="unknown-authority"),
                lambda x: x[0]["original"]["hello"]["binding"].update(key="0" * 64),
                lambda x: x[0]["worker"]["evidence"]["hello"]["binding"].update(volume=str(uuid.uuid4())),
                lambda x: x[0]["original"]["originalOperation"].update(sequence=True),
                lambda x: x[0]["original"].update(clientPrefixSHA256="0" * 64),
                lambda x: x[3]["ready"].update(serviceEpoch=str(uuid.uuid4())),
                lambda x: x[0]["original"].update(signCount=0),
                lambda x: x[0]["worker"]["query"].update(hello={}),
            ):
                changed = copy.deepcopy(args); mutate(changed)
                with self.assertRaises((ValueError, KeyError)): s.correlated_result(*changed)
            if case in ("wrong-volume", "wrong-key", "wrong-role"):
                changed = copy.deepcopy(args)
                changed[2]["slots"] = changed[2]["slots"][:1]
                with self.assertRaises(ValueError): s.correlated_result(*changed)

    def test_transport_and_incomplete_or_contradictory_evidence_rejected(self):
        mutations = (
            lambda v: v["worker"].update(state="failed"),
            lambda v: v["worker"].update(state="observed"),
            lambda v: v["worker"].update(selectedCount=True),
            lambda v: v["worker"]["evidence"].update(errorClass="eof"),
            lambda v: v["worker"]["evidence"].update(rejectedLeafSHA256="0" * 64),
            lambda v: v["worker"]["query"]["workerScope"].update(workerUUID=str(uuid.uuid4())),
            lambda v: v["original"].update(signCount=0),
            lambda v: v["original"].update(bytesWrittenAfterSign=0),
            lambda v: v["original"].update(clientPrefixBytes=True),
            lambda v: v["original"].update(clientPrefixSHA256="0" * 64),
            lambda v: v["original"].update(clientWrittenBytes=131073),
            lambda v: v["original"].update(stage="retained-fd-local-rejection"),
            lambda v: v["original"].update(serverDERSHA256="0" * 64),
            lambda v: v["original"].update(ciphertext="forbidden"),
            lambda v: v["original"].pop("mountIdentitySHA256"),
        )
        for mutate in mutations:
            args = copy.deepcopy(values()); mutate(args[0])
            with self.assertRaises((ValueError, KeyError)): s.correlated_result(*args)


class SameECorrelationNegatives(unittest.TestCase):
    def test_same_e_actual_boundary_and_persisted_retirement_shape(self):
        for case in s.SAME_E_CASES:
            args = values(case)
            self.assertEqual(s.correlated_result(*args), args[0])
            for mutate in (
                lambda x: x[0].pop("retirement"),
                lambda x: x[0]["retirement"].update(operation=x[1]["operationUUID"]),
                lambda x: x[0]["retirement"].update(queryRevision=19),
                lambda x: x[0]["retirement"].update(epoch=str(uuid.uuid4())),
                lambda x: x[0]["retirement"]["controller"].update(epoch=True),
                lambda x: x[0]["retirement"]["receipt"].update(schema=True),
                lambda x: x[0]["retirement"]["attachment"].update(phase="ACTIVE"),
                lambda x: x[0]["retirement"]["attachment"]["binding"].update(key="0" * 64),
                lambda x: x[0]["retirement"]["attachment"]["receipt"].update(revision=19),
                lambda x: x[0]["retirement"]["attachment"]["receipt"].update(revision=20.0),
                lambda x: x[0]["worker"].update(state="observed"),
                lambda x: x[0]["worker"].update(selectedCount=True),
                lambda x: x[0]["worker"]["evidence"].update(errorClass="eof"),
                lambda x: x[0]["worker"]["query"]["workerScope"].update(workerUUID=str(uuid.uuid4())),
                lambda x: x[0]["original"]["rootRequest"].update(node=True),
                lambda x: x[0]["original"].update(clientPrefixBytes=1, clientPrefixSHA256="a" * 64),
                lambda x: x[0]["original"].update(serverDERSHA256="0" * 64),
                lambda x: x[3]["ready"].update(serviceEpoch=str(uuid.uuid4())),
                lambda x: x[0]["original"].pop("rootRequest"),
            ):
                changed = copy.deepcopy(args); mutate(changed)
                with self.assertRaises((ValueError, KeyError)): s.correlated_result(*changed)

    def test_data_requires_actual_correlated_getattr_not_local_close_or_other_operand(self):
        args = values(s.SAME_E_CASES[0])
        for field, value in (("node", 20), ("requestSequence", 6), ("operation", "fsync"),
                             ("authKind", 1), ("noHandle", 1)):
            changed = copy.deepcopy(args); changed[0]["worker"]["evidence"]["admission"][field] = value
            with self.assertRaises(ValueError): s.correlated_result(*changed)
        changed = copy.deepcopy(args)
        changed[0]["original"]["originalOperation"]["errorClass"] = "client-closed-joined"
        with self.assertRaises(ValueError): s.correlated_result(*changed)

    def test_reconnect_requires_exact_original_hello_and_real_auth_boundary(self):
        args = values(s.SAME_E_CASES[1])
        for mutate in (
            lambda x: x[0]["worker"]["evidence"].update(stage="pki-verify-peer", errorClass="unauthorized"),
            lambda x: x[0]["worker"]["evidence"].update(errorClass="conflict"),
            lambda x: x[0]["original"]["hello"]["binding"].update(volume=str(uuid.uuid4())),
            lambda x: x[0]["worker"]["evidence"]["hello"]["binding"].update(prepare=str(uuid.uuid4())),
            lambda x: x[0]["original"].update(signCount=0),
        ):
            changed = copy.deepcopy(args); mutate(changed)
            with self.assertRaises(ValueError): s.correlated_result(*changed)


class ActualFixtureComposition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text()
        cls.tree = ast.parse(cls.source)

    def test_actual_create_function_keeps_other_cases_one_rw_mount(self):
        function = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "create_shared_consumers")
        namespace = {"proof": p}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "actual-fixture-create", "exec"), namespace)
        plan = p.names("a" * 32)
        for case in (None, *s.IMPLEMENTED_CASES, *s.root_backing.ROOT_CASES):
            calls = []
            def create(image, **kwargs):
                calls.append(kwargs)
                return SimpleNamespace(name=kwargs["name"], attrs={"Config": {"Labels": kwargs["labels"]}})
            client = SimpleNamespace(containers=SimpleNamespace(create=create))
            namespace["create_shared_consumers"](client, SimpleNamespace(id="image"), SimpleNamespace(name=plan["volume"]), plan,
                original_consumer_case=case, extra_volume=SimpleNamespace(name="other-volume") if case in ("wrong-volume", *s.root_backing.ROOT_CASES) else None)
            self.assertEqual(len(calls), 2)
            for index, call in enumerate(calls):
                self.assertEqual(len(call["volumes"]), 2 if case in ("wrong-volume", *s.root_backing.ROOT_CASES) else 1)
                self.assertEqual(call["volumes"][plan["volume"]], {"bind": "/data", "mode": "ro" if case == "wrong-mode" and index == 0 else "rw"})
                self.assertTrue(call["read_only"])
            if case in ("wrong-volume", *s.root_backing.ROOT_CASES):
                self.assertEqual(calls[0]["volumes"]["other-volume"], {"bind": "/other", "mode": "rw"})
                self.assertEqual(calls[0]["volumes"], calls[1]["volumes"])
        with self.assertRaises(ValueError):
            namespace["create_shared_consumers"](client, None, None, plan, original_consumer_case="wrong-key", extra_volume=object())

    def test_conditional_image_mount_source_and_runtime_dispatch(self):
        plan = p.names("a" * 32)
        for second in (False, True):
            archive, _ = p.image_archive(b"not-native-probe", plan, second_mount=second)
            with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
                with tarfile.open(fileobj=io.BytesIO(outer.extractfile("layer.tar").read())) as layer:
                    self.assertEqual("other" in layer.getnames(), second)
        runner = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_prepare_case")
        calls = [n for n in ast.walk(runner) if isinstance(n, ast.Call)]
        archive = next(n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == "image_archive"
            and any(k.arg == "second_mount" for k in n.keywords))
        self.assertEqual(ast.unparse(next(k.value for k in archive.keywords if k.arg == "second_mount")), "original_consumer_case == 'wrong-volume' or root_case")
        creation = next(n for n in calls if isinstance(n.func, ast.Name) and n.func.id == "create_shared_consumers")
        self.assertEqual({k.arg: ast.unparse(k.value) for k in creation.keywords},
            dict(original_consumer_case="original_consumer_case", extra_volume="extra_volume", two_volume="two_volume"))
        # Execute the ACTUAL conditional volume setup with a fake Docker client:
        # these are composition checks, not native acceptance.
        branch = next(n for n in ast.walk(runner) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "two_volume or original_consumer_case == 'wrong-volume' or root_case"
            and any(isinstance(x, ast.Assign) and any(isinstance(y, ast.Name) and y.id == "extra_plan" for y in x.targets) for x in n.body))
        for case in (None, *s.IMPLEMENTED_CASES, *s.root_backing.ROOT_CASES):
            made = []
            def volume_create(name, labels):
                made.append(name); return SimpleNamespace(name=name, attrs={"Labels": labels})
            ns = dict(proof=p, plan=plan, original_consumer_case=case, root_case=case in s.root_backing.ROOT_CASES,
                two_volume=False, extra_plan=None, extra_volume=None,
                client=SimpleNamespace(volumes=SimpleNamespace(create=volume_create)))
            exec(compile(ast.Module(body=[branch], type_ignores=[]), "actual-conditional-volume", "exec"), ns)
            self.assertEqual(made, [plan["volume"] + "-other"] if case in ("wrong-volume", *s.root_backing.ROOT_CASES) else [])

    def test_writer_operations_bracket_paired_carrier_and_share_exec_path(self):
        live = (ROOT / "Tests/Compatibility/managed_stale_consumer.py").read_text()
        before = live.index('            writer_positive(observe, peer, baseline)')
        after = live.rindex('                writer_positive(observe, peer, baseline)')
        self.assertLess(before, live.index('queue.publish("original-consumer.capture.json"'))
        self.assertLess(live.index('correlated_result(result,'), after)
        self.assertLess(live.index('surviving_hosts(census,'), after)
        self.assertLess(live.index('p.snapshot(recovered, baseline=baseline)'), after)
        self.assertNotIn('observe("empty", peer)', live)
        self.assertNotIn('baseline=None', live)
        self.assertEqual(live.count('writer_positive(observe, peer, baseline)'), 3)  # Definition and both actual callers.
        self.assertIn('peer_proof, _, validate_peer = stack.enter_context(p.workload_owner', live)
        self.assertIn('exec_create(selected.id, ["/probe", "worker-verify" if command == "worker-verify-written" else command]', self.source)
        self.assertIn('status["ExitCode"] == 0', self.source)
        self.assertIn('proof.snapshot(value, command)', self.source)
        self.assertIn('fixture_mounts(saved, normal, state, plan, original_consumer_case, extra_plan)', self.source)

    def test_writer_positive_executes_both_closed_validations_not_just_dispatch(self):
        # Engine-free composition only: the deployed probe must actually perform
        # the fixed write/fsync/readback/unlink/fsync before reporting this ACK.
        import stat
        def meta(mode):
            return dict(mode=mode, uid=10001, gid=10002, atimeNS=p.MTIME * 10**9, mtimeNS=p.MTIME * 10**9, xattrs={})
        baseline = dict(command="snapshot", entries=["a", "z"], root=meta(stat.S_IFDIR | 0o750),
            files={name: dict(**meta(stat.S_IFREG | 0o640), size=len(raw), sha256=p.digest(raw), nlink=1) for name, raw in p.FILES.items()},
            mountinfo="23 10 0:40 / /data ro - fuse.managed-v3 managed-v3 rw\\n", parentFsynced=False)
        written = copy.deepcopy(baseline)
        written.update(command="writer", parentFsynced=True,
            mountinfo="24 10 0:41 / /data rw - fuse.managed-v3 managed-v3 rw\\n")
        peer = object()
        def run(outputs):
            calls = []
            def observe(*args):
                calls.append(args)
                return outputs[len(calls) - 1]
            s.writer_positive(observe, peer, baseline)
            self.assertEqual(calls, [("writer", peer), ("snapshot",)])
        run([written, baseline])
        for index, mutate in (
            (0, lambda v: v.update(command="snapshot", parentFsynced=False)),
            (0, lambda v: v.update(command="empty", entries=[], files={})),
            (0, lambda v: v.update(parentFsynced=False)),
            (0, lambda v: v.update(mountinfo=baseline["mountinfo"])),
            (1, lambda v: v["entries"].append(".rtm103-writer")),
            (1, lambda v: v["files"]["a"].update(sha256="0" * 64)),
            (1, lambda v: v["root"].update(atimeNS=1)),
            (1, lambda v: v.update(mountinfo=written["mountinfo"])),
        ):
            outputs = copy.deepcopy([written, baseline]); mutate(outputs[index])
            with self.assertRaises(ValueError): run(outputs)
        def failed_exec(*args): raise RuntimeError("actual writer nonzero exit")
        with self.assertRaises(RuntimeError): s.writer_positive(failed_exec, peer, baseline)

    def test_actual_fixture_receipts_and_saved_mounts_no_rw_projection(self):
        for case in ("wrong-volume", "wrong-mode"):
            _, binding, intent, _ = values(case)[:4]
            plan = p.names("a" * 32)
            extra = {**plan, "volume": plan["volume"] + "-other"}
            slots = s.runtime_slots(intent, case)
            mounts = [dict(volume=v["volume"], destination="/data" if n == 0 else "/other", subpath="", mode=v["mode"]) for n, v in enumerate(slots)]
            intent.update(phase="running", mounts=mounts, prepareCompleted=True, cleanUnmount=True,
                guestCompletion=dict(prepare=intent["prepare"], containerInstance=intent["containerInstance"], launch=intent["launch"],
                    succeeded=True, cleanCopyUp=True, evidenceDigest="a" * 64))
            intent["slots"] = list(slots)
            for slot in slots:
                prepare = dict(slot, attachment=str(uuid.uuid4()), role="prepare", mode="read-write", key="7" * 64)
                prepare["receipt"] = dict(store=intent["store"], volume=slot["volume"], attachment=prepare["attachment"], prepare=intent["prepare"], launch=intent["launch"], revision=3)
                intent["slots"].append(prepare)
            manifest = dict(store=intent["store"])
            state = dict(store=intent["store"], reconciliationRequired=False, revision=5, intents={intent["id"]: intent},
                volumes={v["volume"]: dict(id=v["volume"], name=(plan if n == 0 else extra)["volume"], createdRevision=1) for n, v in enumerate(slots)})
            saved = dict(id=intent["container"], instanceID=intent["containerInstance"], mounts=[dict(kind="volume", source=(plan if n == 0 else extra)["volume"],
                destination=m["destination"], readOnly=m["mode"] == "read-only", noCopy=False) for n, m in enumerate(mounts)])
            args = (manifest, state, plan, intent["container"], intent["id"], case, extra)
            self.assertEqual(s.fixture_receipts(*args), intent)
            s.fixture_mounts(saved, intent, state, plan, case, extra)
            for mutate in (
                lambda i: i.update(prepareCompleted=False),
                lambda i: i["mounts"][0].update(mode="read-write" if case == "wrong-mode" else "read-only"),
                lambda i: i["slots"][0].update(receipt={"revision": 3}),
                lambda i: i["slots"][-1]["receipt"].update(volume=str(uuid.uuid4())),
                lambda i: i["slots"].append(dict(i["slots"][-1])),
            ):
                bad = copy.deepcopy(args); mutate(bad[1]["intents"][intent["id"]])
                with self.assertRaises(ValueError): s.fixture_receipts(*bad)
            bad_saved = copy.deepcopy(saved); bad_saved["mounts"][0]["readOnly"] = not bad_saved["mounts"][0]["readOnly"]
            with self.assertRaises(ValueError): s.fixture_mounts(bad_saved, intent, state, plan, case, extra)
            intent["phase"] = "retired"
            for slot in slots:
                slot["receipt"] = dict(store=intent["store"], volume=slot["volume"], attachment=slot["attachment"], launch=intent["launch"], revision=5)
            self.assertEqual(s.fixture_receipts(*args, stopped=True), intent)

    def test_mounted_modes_and_second_mount_are_actual_observations(self):
        rw = "1 0 0:1 / /data rw - fuse.managed-v3 managed-v3 rw\n"
        other = "2 0 0:2 / /other rw - fuse.managed-v3 managed-v3 rw\n"
        s.mounted_fixture(dict(mountinfo=rw + other), "wrong-volume")
        s.mounted_fixture(dict(mountinfo=rw.replace('/data rw', '/data ro')), "wrong-mode")
        for text, case in ((rw, "wrong-volume"), (rw, "wrong-mode"), (rw.replace('fuse.managed-v3', 'ext4'), "wrong-key")):
            with self.assertRaises(ValueError): s.mounted_fixture(dict(mountinfo=text), case)


class WrongVolumeModeEvidence(unittest.TestCase):
    def test_exact_runtime_volume_not_prepare_or_extra_slot(self):
        args = values("wrong-volume")
        self.assertEqual(s.correlated_result(*args), args[0])
        for mutation in (
            lambda x: x[2]["slots"].pop(),
            lambda x: x[2]["slots"][-1].update(role="prepare"),
            lambda x: x[2]["slots"][-1].update(receipt={"revision": 4}),
            lambda x: x[2]["slots"][-1].update(key=x[2]["slots"][0]["key"]),
            lambda x: x[2]["slots"][-1].update(volume=x[2]["slots"][0]["volume"]),
            lambda x: x[2]["slots"].append(dict(x[2]["slots"][-1])),
            lambda x: x[1].update(targetAttachment=x[2]["slots"][-1]["attachment"]),
            lambda x: x[0]["original"]["arm"].update(otherVolume=x[2]["slots"][-1]["volume"]),
        ):
            changed = copy.deepcopy(args); mutation(changed)
            with self.assertRaises(ValueError): s.correlated_result(*changed)

    def test_wrong_mode_only_ro_to_rw_exact_both_hellos(self):
        args = values("wrong-mode")
        self.assertEqual(s.correlated_result(*args), args[0])
        for mutation in (
            lambda x: x[2]["slots"][0].update(mode="read-write"),
            lambda x: x[0]["original"]["hello"]["binding"].update(mode="read-only"),
            lambda x: x[0]["worker"]["evidence"]["hello"]["binding"].update(mode="read-only"),
        ):
            changed = copy.deepcopy(args); mutation(changed)
            with self.assertRaises(ValueError): s.correlated_result(*changed)


if __name__ == "__main__": unittest.main()
