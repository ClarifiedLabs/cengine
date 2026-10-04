"""Strict control-denial supplement to the genuine original GETATTR projection.

These records do not create authority. Called only after the same-E wire proof.
"""
import copy
import managed_prepare_faults as p
import managed_root_projection as root
from managed_prepare_storage_vm_faults import bounded_base64


def validate(value, binding, intent, boot):
    try:
        _validate(value, binding, intent, boot)
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        raise ValueError("malformed registration proof") from error
    return value


def _validate(value, binding, intent, boot):
    root.bounded_tree(value)
    proof, retired = value["registration"], value["retirement"]
    root.shape(proof, {"binding", "operation", "originalRegisterOperation", "attempted", "denial", "authority", "service", "peer", "observed"})
    root.equal(proof["binding"], binding)
    root.equal(proof["service"], {k: boot["ready"][k] for k in ("storeUUID", "serviceEpoch", "workerUUID")})
    observed = copy.deepcopy(value["worker"]); observed["state"] = "observed"
    root.equal(proof["observed"], observed)
    peer = proof["peer"]; root.shape(peer, {"tlsRootDER", "serverDER", "serverKey", "dataAddress"})
    for key in ("tlsRootDER", "serverDER", "serverKey"): root.equal(peer[key], boot["ready"][key])
    bounded_base64(peer["tlsRootDER"], 16384); bounded_base64(peer["serverDER"], 16384); p.pin(peer["serverKey"])
    p.require(type(peer["dataAddress"]) is str and 0 < len(peer["dataAddress"].encode()) <= 1024, "bounded retained transport")
    slot = next(item for item in intent["slots"] if item["attachment"] == binding["targetAttachment"])
    root.equal(proof["originalRegisterOperation"], slot["registerOperation"])
    p.uid(proof["operation"]); p.uid(proof["originalRegisterOperation"])
    p.require(proof["operation"] != retired["operation"] and proof["originalRegisterOperation"] != retired["operation"], "distinct real operations")
    authority = proof["authority"]; root.shape(authority, {"before", "atProbe", "after", "retirement"})
    root.equal(authority["retirement"], retired)
    identity = root.lifecycle.comparison_identity(boot)
    for key in ("before", "atProbe", "after"): root.snapshot(authority[key], binding["scope"], identity)
    before, at_probe = authority["before"], authority["atProbe"]
    root.equal(authority["after"], at_probe)
    exact = retired["attachment"]["binding"]
    root.equal(before["attachments"][exact["attachment"]], dict(binding=exact, phase="ACTIVE"))
    p.require(before["volume_lifecycles"][exact["volume"]]["phase"] == "READY"
        and retired["receipt"]["revision"] > before["revision"]
        and retired["queryRevision"] == at_probe["revision"], "actual advancing retirement")
    expected = copy.deepcopy(before); expected["revision"] = at_probe["revision"]
    expected["attachments"][exact["attachment"]] = retired["attachment"]
    root.equal(at_probe, expected)
    attempted = proof["attempted"]; root.runtime(attempted, exact["store"])
    if binding["caseName"] == "delayed-registration":
        root.equal(proof["denial"], "BLOCKED"); root.equal(attempted, exact)
        root.equal(proof["operation"], proof["originalRegisterOperation"])
    else:
        root.equal(binding["caseName"], "attachment-key-reuse"); root.equal(proof["denial"], "CONFLICT")
        p.require(proof["operation"] != proof["originalRegisterOperation"]
            and attempted["attachment"] not in before["attachments"], "new attachment/op, never key revival")
        root.equal(attempted, dict(exact, attachment=attempted["attachment"]))
    positive, original = value["positive"], value["original"]
    expected = copy.deepcopy(original)
    p.integer(positive["rootRequest"]["requestSequence"], original["rootRequest"]["requestSequence"] - 1, 1)
    expected.update(stage="begun", serverDERSHA256="",
        rootRequest=dict(node=original["rootRequest"]["node"], requestSequence=positive["rootRequest"]["requestSequence"]),
        originalOperation=dict(kind="data-getattr-root", sequence=1, errorClass="ok"))
    root.equal(positive, expected)
