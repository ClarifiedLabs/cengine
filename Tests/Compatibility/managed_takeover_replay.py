"""Public-grant replay CONTROL LEG only; never RTM103/native acceptance.

ROOT signatures/recipient death are verified by the actual signed Runtime/helper.
This observer correlates their immutable public transcript. A resumed Arm is an
old positive, NOT a fresh GETATTR or evidence that any DATA request was denied.
"""
from __future__ import annotations
import base64
import copy
import signal
import time
import uuid

import managed_prepare_faults as p
import managed_storage_recovery as recovery
import managed_takeover_lifecycle_evidence as lifecycle

VERSION = "original-takeover-public.v1"


def _binary(value, maximum):
    p.require(type(value) is str, "base64 string")
    try: data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError): raise recovery.ProofFailure("public base64") from None
    p.require(0 < len(data) <= maximum and base64.b64encode(data).decode() == value, "bounded canonical base64")
    return data


def transition(value):
    p.exact(value, {"issue", "issued", "confirm", "confirmed"})
    values = []
    for field, operation in (("issue", "issueTakeoverGrant"), ("issued", "issueTakeoverGrant"),
                             ("confirm", "confirmTakeover"), ("confirmed", "confirmTakeover")):
        wire = p.decode(_binary(value[field], 65536), canonical_only=False)
        p.exact(wire, {"version", "operation", "request_id", "body"})
        p.uid(wire["request_id"])
        p.require(wire["version"] == "bootstrap.v1" and wire["operation"] == operation, "ROOT envelope")
        values.append(wire)
    issue, issued, confirm, confirmed = values
    i, signed, c, current = [v["body"] for v in values]
    p.exact(i, {"grant_id", "store", "expected_epoch", "candidate"})
    p.exact(i["candidate"], {"public_data", "child_pid_hint", "incarnation_id"})
    p.uid(i["candidate"]["incarnation_id"]); p.integer(i["candidate"]["child_pid_hint"], 2**31-1, 1)
    key = p.digest(_binary(i["candidate"]["public_data"], 128))
    p.exact(signed, {"grant", "signature"}); g = signed["grant"]
    p.exact(g, {"id", "store", "expected_epoch", "new_key"})
    p.uid(g["id"]); p.uid(g["store"]); p.pin(g["new_key"])
    p.integer(g["expected_epoch"], 2**64-2, 1); p.integer(i["expected_epoch"], 2**64-2, 1)
    p.require(len(_binary(signed["signature"], 64)) == 64, "signature length, not authority")
    p.exact(c, {"store", "grant_id", "controller"}); p.exact(current, {"controller"})
    for controller in (c["controller"], current["controller"]):
        p.exact(controller, {"epoch", "key"}); p.integer(controller["epoch"], 2**64-1, 2); p.pin(controller["key"])
    p.require(issue["request_id"] == issued["request_id"] and confirm["request_id"] == confirmed["request_id"], "ROOT correlation")
    p.require(g == dict(id=i["grant_id"], store=i["store"], expected_epoch=i["expected_epoch"], new_key=key)
        and c == dict(store=g["store"], grant_id=g["id"], controller=current["controller"])
        and current["controller"] == dict(epoch=g["expected_epoch"]+1, key=key), "exact confirmed public grant")
    return signed, i["candidate"]


def same_service_step(before, after):
    if lifecycle.is_v2(before) or lifecycle.is_v2(after):
        return lifecycle.same_service_step(before, after)
    old, new = recovery.owner_proof(before), recovery.owner_proof(after)
    for key in ("root", "backing", "bytes", "rootKeyHash", "store", "ext4UUID", "shimLaunchUUID", "guestBootNonce", "serviceEpoch"):
        p.require(old[key] == new[key], "same retained service/disk " + key)
    p.require(after.get("workerReplacements") == before.get("workerReplacements")
        and after.get("serviceTransitions") == before.get("serviceTransitions") and after["boot"] == before["boot"], "no substituted worker/VM boot")
    p.require(after["transitions"][:-1] == before["transitions"] and len(after["transitions"]) == len(before["transitions"])+1
        and new["controllerEpoch"] == old["controllerEpoch"]+1 and new["revision"] > old["revision"], "exact single controller successor")
    return transition(after["transitions"][-1])


def control_result(before, after, capture, begun, denied, confirmed):
    p.require(lifecycle.is_v2(before) == lifecycle.is_v2(after), "same explicit replay owner format")
    p.exact(capture, {"version", "requestID", "store", "epoch", "serviceEpoch"} | ({"original"} if "original" in capture else set()))
    p.uid(capture["requestID"]); p.integer(capture["epoch"], 2**64-2, 2)
    owner = lifecycle.owner(before)
    p.require(capture["version"] == VERSION and capture["store"] == owner["store"]
        and capture["epoch"] == owner["controllerEpoch"] and capture["serviceEpoch"] == owner["serviceEpoch"], "capture scope")
    if lifecycle.is_v2(before):
        return lifecycle.public_control_result(before, after, capture["requestID"], begun, denied, confirmed)
    p.require(before["transitions"] and p.canonical(begun) == p.canonical(before["transitions"][-1]), "persisted prior completion, not supplied grant")
    old, _ = transition(begun); pending, candidate = same_service_step(before, after)
    p.require(p.canonical(confirmed) == p.canonical(after["transitions"][-1]), "committed actual confirmation")
    p.exact(denied, {"request_id", "version", "store", "service_epoch", "incarnation_id", "signed", "pending", "denied"})
    p.exact(denied["denied"], {"id", "error"}); p.integer(denied["denied"]["id"], 2**64-1, 1)
    p.require(denied["denied"]["error"] == "UNAUTHORIZED", "actual remote nonzero-ID denial, not CURRENT preflight")
    p.require(denied["request_id"] == capture["requestID"] and denied["version"] == VERSION
        and denied["store"] == capture["store"] and denied["service_epoch"] == capture["serviceEpoch"]
        and denied["incarnation_id"] == candidate["incarnation_id"]
        and p.canonical(denied["signed"]) == p.canonical(old) and p.canonical(denied["pending"]) == p.canonical(pending["grant"])
        and old["grant"]["expected_epoch"]+1 == pending["grant"]["expected_epoch"]
        and old["grant"]["new_key"] != pending["grant"]["new_key"], "exact old bytes on actual new successor")
    return dict(controlLegVerified=True, fullAcceptance=False, nativeAcceptance=False,
        requestID=capture["requestID"], denied=copy.deepcopy(denied), confirmed=copy.deepcopy(confirmed))


def validate_original_arm(original, armed):
    import managed_stale_consumer as stale
    p.exact(original, stale.BINDING_FIELDS)
    p.require(original["caseName"] == "same-e-existing-data" and type(original["version"]) is int
        and original["version"] == 4 and original["profile"] == p.FULL_PROFILE, "original v4 GETATTR carrier")
    expected_arm = {k: original[k] for k in ("version", "profile", "requestID", "operationUUID", "caseName", "scope", "targetAttachment")}
    expected_arm.update(binding=original["boot"], leafSHA256=original["certificateSHA256"])
    p.exact(armed, stale.EVIDENCE_FIELDS | {"rootRequest"})
    p.require(p.canonical(armed["arm"]) == p.canonical(expected_arm)
        and p.canonical(armed["scope"]) == p.canonical(original["scope"])
        and armed["keySHA256"] == original["key"] and armed["stage"] == "armed-mounted-positive", "pre-restart exact original")
    p.pin(armed["mountIdentitySHA256"])
    p.exact(armed["rootRequest"], {"node", "requestSequence"})
    for n in armed["rootRequest"].values(): p.integer(n, 2**64-1, 1)
    p.require(armed["fdOperation"] == "fsync-directory", "mount prerequisite only")
    p.integer(armed["fdSequence"], 1, 1)
    p.require(p.canonical(armed["originalOperation"]) == p.canonical(dict(kind="data-getattr-root", sequence=1, errorClass="ok")), "actual first GETATTR")
    for k in ("serverDERSHA256", "signInputSHA256", "clientPrefixSHA256", "localError"):
        p.require(armed[k] == "", "no TLS denial " + k)
    for k in ("signCount", "bytesWrittenAfterSign", "clientWrittenBytes", "clientPrefixBytes"): p.integer(armed[k], 0, 0)
    return expected_arm


def recovered_original_positive(value, original, armed):
    """Project actual sealed post-recovery FIFO proof, not control acceptance.

    Caller must obtain original/armed from the pinned PRE-restart activation;
    neither this projection nor an old Arm reconstructs a live capability.
    """
    import managed_stale_consumer as stale
    p.exact(value, {"binding", "resumed", "begun", "positive", "released"})
    expected_arm = validate_original_arm(original, armed)
    p.require(p.canonical(value["binding"]) == p.canonical(original), "unchanged original binding")
    p.require(p.canonical(value["resumed"]) == p.canonical(armed), "same shim retained positive")
    begun = copy.deepcopy(armed); begun["stage"] = "begun"
    p.require(p.canonical(value["begun"]) == p.canonical(begun), "Begin cannot replace prior proof")
    positive = copy.deepcopy(begun); positive["stage"] = "original-data-positive"
    actual = value["positive"]; p.exact(actual, stale.EVIDENCE_FIELDS | {"rootRequest"})
    p.exact(actual["rootRequest"], {"node", "requestSequence"})
    for n in actual["rootRequest"].values(): p.integer(n, 2**64-1, 1)
    p.require(actual["rootRequest"]["node"] == armed["rootRequest"]["node"]
        and actual["rootRequest"]["requestSequence"] > armed["rootRequest"]["requestSequence"], "new matching original FIFO operation")
    positive["rootRequest"] = actual["rootRequest"]; positive["originalOperation"]["sequence"] = 2
    p.require(p.canonical(actual) == p.canonical(positive), "exact positive not cached/snapshot/denial")
    p.require(p.canonical(value["released"]) == p.canonical(dict(arm=expected_arm, stage="released")), "joined original release")
    return dict(originalOperationVerified=True, fullAcceptance=False, nativeAcceptance=False)


def run_control_restarts(daemon, *, remaining, record, original=None):
    """Actual fixture restart helper; deliberately NOT wired to a case selector.

    Uses only the fixture's owned Popen through its existing bounded restart API.
    No PID-selected signals/launchers. Caller campaign must allow each existing
    180s startup +15s stop bound. No callbacks may synthesize original evidence.
    The original-observation/full-case integration is still required.
    """
    if original is not None:
        p.require(remaining() >= 390, "both existing restart budgets before first stop")
    def owner(): return lifecycle.read_owner(daemon.root)
    initial, _ = owner(); proof = lifecycle.owner(initial)
    p.require(proof["controllerEpoch"] == 1, "fresh C1 owner")
    if lifecycle.is_v2(initial):
        p.require(initial["checkpoint"]["current"]["original"]["signed"]["grant"]["operation"] == "initialize",
            "actual lifecycle C1 initialization")
    else:
        p.require(not initial["transitions"], "fresh legacy C1 history")
    before = initial
    for turn in range(2):
        p.require(remaining() >= 195 and daemon.process is not None and daemon.process.poll() is None, "bounded owned restart")
        if turn == 0:
            api = daemon.process
            daemon.restart(kill=True)
            p.require(api.poll() == -signal.SIGKILL, "joined owned API SIGKILL")
            before, owner_hash = owner(); same_service_step(initial, before)
            record("takeover-first-confirmed", owner=lifecycle.owner_evidence(daemon.root, before, owner_hash))
            continue
        current = lifecycle.owner(before)
        capture = dict(version=VERSION, requestID=str(uuid.uuid4()), store=current["store"], epoch=current["controllerEpoch"], serviceEpoch=current["serviceEpoch"])
        with p.Directory(daemon.root / "managed-prepare-compatibility") as queue:
            if original is not None:
                capture["original"] = original.prepare(before, queue)
            # Arm does not start Begin. Still refuse a restart that cannot fit
            # the existing stop/start bound after real workload setup.
            p.require(remaining() >= 195 and daemon.process.poll() is None, "bounded final owned restart")
            queue.publish("public-takeover.capture.json", capture)
            api = daemon.process
            daemon.restart(kill=True)
            p.require(api.poll() == -signal.SIGKILL, "joined owned API SIGKILL")
            if original is not None:
                original.api_restarted(api)
            artifacts = {}; pinned_artifacts = {}
            phases = ("begun", "denied") + (("attestation",) if original is not None else ()) + ("confirmed",) + (("resumed", "positive", "registry") if original is not None else ())
            for phase in phases:
                name = capture["requestID"] + ".public-takeover." + phase + ".json"
                while True:
                    remaining(); queue.validate()
                    try:
                        pinned_artifacts[name] = queue.read(name, 65536, pin_file=True)
                        raw = pinned_artifacts[name][0]; break
                    except FileNotFoundError: time.sleep(0.01)
                artifacts[phase] = p.decode(raw, canonical_only=False)
            after, _ = owner()
            result = control_result(before, after, capture, **{k:artifacts[k] for k in ("begun", "denied", "confirmed")})
            if original is not None:
                result.update(original.finish(after, queue, artifacts, capture["requestID"]))
            for name, pinned in pinned_artifacts.items():
                p.require(queue.read(name, 65536) == pinned, "final immutable replay evidence")
            record("takeover-control-leg", result=result)
            return result
