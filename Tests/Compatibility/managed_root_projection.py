"""Closed v6 root proof projection. Only live pinned owner records may call this.

Numeric collisions are legitimate B-local grants: successful replay must read B,
never fabricated denial or A content. JSON itself conveys no authority.
"""
import copy
import managed_prepare_faults as p
import managed_root_backing as backing
import managed_original_lifecycle_evidence as lifecycle
from managed_prepare_storage_vm_faults import bounded_base64

U64 = 2**64 - 1


def equal(value, expected):
    p.require(p.canonical(value) == p.canonical(expected), "exact typed root proof correlation")


def shape(value, required, optional=()):
    p.require(type(value) is dict, "root proof object")
    p.require(set(required) <= set(value) <= set(required) | set(optional) and all(v is not None for v in value.values()), "closed non-null root proof shape")


def root_id(value, creating=False):
    p.exact(value, {"device", "inode"})
    p.integer(value["device"], U64); p.integer(value["inode"], U64, 0 if creating else 1)
    return value["device"], value["inode"]


def runtime(value, store):
    shape(value, {"store", "volume", "attachment", "container", "launch", "key", "role", "mode"}, {"prepare"})
    for key in ("store", "volume", "attachment", "launch"): p.uid(value[key])
    for key in ("container", "key"): p.pin(value[key])
    p.require(value["store"] == store and value["mode"] in ("read-only", "read-write"), "exact authority context")
    p.require(value["role"] in ("prepare", "runtime") and ("prepare" in value) == (value["role"] == "prepare"), "exact authority role")
    if "prepare" in value: p.uid(value["prepare"])


def receipt(value, binding, revision):
    expected = dict(schema=3, **{k: binding[k] for k in ("store", "volume", "attachment", "launch")}, revision=value["revision"])
    if "prepare" in binding: expected["prepare"] = binding["prepare"]
    equal(value, expected); p.integer(value["revision"], revision, 1)


def snapshot(value, scope, lifecycle_identity=None):
    p.exact(value, {"schema", "revision", "store", "epoch", "controller", "volumes", "volume_lifecycles", "attachments", "prepares"})
    schema = 3 if lifecycle_identity is None else 4
    if lifecycle_identity is not None:
        p.exact(lifecycle_identity, {"store", "generation", "binding"})
        p.uid(lifecycle_identity["store"]); p.integer(lifecycle_identity["generation"], U64, 1); p.pin(lifecycle_identity["binding"])
        equal(lifecycle_identity["store"], scope["store"])
    p.integer(value["schema"], schema, schema); p.integer(value["revision"], U64, 1)
    equal(value["epoch"], scope["serviceEpoch"])
    equal(value["controller"], dict(epoch=scope["controllerEpoch"], key=scope["controllerKey"]))
    store = value["store"]; p.exact(store, {"id", "device_id", "root", "exports"})
    equal(store["id"], scope["store"])
    p.require(type(store["device_id"]) is str and 0 < len(store["device_id"].encode()) <= 256, "bounded actual device identity")
    device, _ = root_id(store["root"]); p.require(root_id(store["exports"])[0] == device, "same exports device")
    for key in ("volumes", "volume_lifecycles", "attachments", "prepares"):
        p.require(type(value[key]) is dict, "registry map")
    volumes, lives, attachments, prepares = (value[k] for k in ("volumes", "volume_lifecycles", "attachments", "prepares"))
    p.require(set(volumes) == set(lives), "complete volume lifecycles")
    names, roots = set(), set()
    for ident, volume in volumes.items():
        p.uid(ident); p.exact(volume, {"id", "name", "root"}); equal(volume["id"], ident)
        p.require(type(volume["name"]) is str and 0 < len(volume["name"].encode()) <= 255
            and volume["name"] not in (".", "..") and "/" not in volume["name"] and "\0" not in volume["name"], "bounded safe volume name")
        life = lives[ident]; shape(life, {"phase"}, {"create", "delete", "created_revision", "deleted_revision"})
        phase = life["phase"]; p.require(phase in ("CREATING", "READY", "DELETING", "DELETED"), "volume phase")
        created, deleted = life.get("created_revision", 0), life.get("deleted_revision", 0)
        for key in ("created_revision", "deleted_revision"):
            if key in life: p.integer(life[key], value["revision"], 1)
        for key in ("create", "delete"):
            if key in life: p.uid(life[key])
        p.require(not created or "create" in life, "created receipt has operation")
        identity = root_id(volume["root"], phase == "CREATING")
        if phase == "CREATING": p.require("create" in life and created == 0 and identity == (0, 0), "pending create")
        else: p.require(identity[0] == device and ("create" not in life or created > 0), "created root")
        if phase in ("DELETING", "DELETED"):
            p.require("delete" in life and (phase == "DELETED") == (deleted > 0) and (not deleted or deleted > created), "exact delete lifecycle")
        else: p.require("delete" not in life and deleted == 0, "no unrelated deletion")
        if phase != "DELETED":
            p.require(volume["name"] not in names and (phase == "CREATING" or identity not in roots), "unique registry volume")
            names.add(volume["name"])
            if phase != "CREATING": roots.add(identity)
    keys = {scope["controllerKey"]}
    for ident, item in attachments.items():
        shape(item, {"binding", "phase"}, {"receipt", "retirement"}); b = item["binding"]; runtime(b, scope["store"])
        p.require(ident == b["attachment"] and b["volume"] in volumes and b["key"] not in keys, "unique actual attachment/key")
        keys.add(b["key"]); phase = item["phase"]
        p.require(phase in ("RESERVED", "ACTIVE", "RETIRING", "DRAINED") and (lives[b["volume"]]["phase"] == "READY" or phase == "DRAINED"), "attachment phase")
        if "retirement" in item:
            p.uid(item["retirement"]); p.require(phase in ("RETIRING", "DRAINED"), "retiring authority")
        if phase == "DRAINED":
            p.require("retirement" in item and "receipt" in item, "real drained receipt")
            receipt(item["receipt"], b, value["revision"])
        else: p.require("receipt" not in item, "no premature receipt")
        if b["role"] == "prepare":
            p.require(b["prepare"] in prepares and b in prepares[b["prepare"]]["attachments"], "prepare registry membership")
        else: p.require(phase != "RESERVED", "runtime not reserved")
    pending = set()
    for ident, item in prepares.items():
        fields = {"id", "attachments", "phase"} | ({"context"} if schema == 4 else set())
        p.uid(ident); shape(item, fields, {"successor", "attestation"}); equal(item["id"], ident)
        if schema == 4:
            context = item["context"]
            p.exact(context, {"service_epoch", "controller_epoch", "controller_key"})
            p.uid(context["service_epoch"]); p.pin(context["controller_key"])
            p.integer(context["controller_epoch"], scope["controllerEpoch"], 1)
            if context["controller_epoch"] == scope["controllerEpoch"]:
                equal(context["controller_key"], scope["controllerKey"])
        pair = item["attachments"]; p.require(type(pair) is list and pair, "nonempty prepare slots")
        order = [b["volume"] for b in pair]; p.require(order == sorted(set(order)), "ordered unique prepare volumes")
        phase = item["phase"]; p.require(phase in ("PENDING", "COMPLETED", "REPLACED"), "prepare phase")
        for b in pair:
            runtime(b, scope["store"]); equal(b["role"], "prepare"); equal(b["prepare"], ident)
            remote = attachments[b["attachment"]]; equal(remote["binding"], b)
            if phase == "PENDING":
                p.require(lives[b["volume"]]["phase"] == "READY" and b["volume"] not in pending, "exclusive pending prepare")
                pending.add(b["volume"])
            else: equal(remote["phase"], "DRAINED")
        if phase == "PENDING": p.exact(item, fields)
        elif phase == "COMPLETED":
            p.exact(item, fields | {"attestation"})
            equal(item["attestation"], dict(prepare=ident, succeeded=True, clean_copy_up=True))
        else:
            p.exact(item, fields | {"successor"}); p.uid(item["successor"])
            p.require(item["successor"] != ident and item["successor"] in prepares, "real successor")
            equal([b["volume"] for b in prepares[item["successor"]]["attachments"]], order)


def bounded_tree(value):
    # Before cross-references, reject explicit null/float and bound every tree.
    # Missing required members are still rejected by the closed shapes below.
    pending = [(value, 0)]; count = 0
    while pending:
        item, depth = pending.pop(); count += 1
        p.require(depth <= 64 and count <= 32768 and type(item) in (dict, list, str, int, bool), "bounded non-null integer JSON proof")
        if type(item) is dict:
            p.require(all(type(k) is str for k in item), "JSON object keys")
            pending.extend((v, depth+1) for v in item.values())
        elif type(item) is list: pending.extend((v, depth+1) for v in item)


def result(value, binding, intent, boot, evidence_fields, baseline_ack):
    bounded_tree(value)
    case = binding["caseName"]; p.require(case in backing.ROOT_CASES, "finite root case")
    retired = case == "retired-root-grant-replay"
    p.exact(value, {"version", "binding", "service", "peer", "baseline", "positive", "original", "authority"} | ({"worker", "finalized"} if retired else set()))
    p.integer(value["version"], 1, 1); p.integer(binding["version"], 6, 6); equal(value["binding"], binding)
    ready = boot["ready"]; scope = binding["scope"]
    equal(value["service"], {k: ready[k] for k in ("storeUUID", "serviceEpoch", "workerUUID")})
    equal({k: ready[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")}, {k: scope[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")})
    equal(ready["storeUUID"], scope["store"])
    p.exact(value["peer"], {"tlsRootDER", "serverDER", "serverKey", "dataAddress"})
    for key in ("tlsRootDER", "serverDER", "serverKey"): equal(value["peer"][key], ready[key])
    p.require(type(value["peer"]["dataAddress"]) is str and 0 < len(value["peer"]["dataAddress"].encode()) <= 256, "bounded original transport address; not authority")
    server_hash = p.digest(bounded_base64(value["peer"]["serverDER"], 16384))
    bounded_base64(value["peer"]["tlsRootDER"], 16384); p.pin(value["peer"]["serverKey"])
    backing.baseline_accepted(value["baseline"], baseline_ack); equal(baseline_ack["binding"], binding)
    arm = dict(version=6, profile=p.FULL_PROFILE, requestID=binding["requestID"], operationUUID=binding["operationUUID"], caseName=case,
        binding=binding["boot"], scope=scope, targetAttachment=binding["targetAttachment"], leafSHA256=binding["certificateSHA256"])
    slots = sorted((s for s in intent["slots"] if s["role"] == "runtime"), key=lambda s: s["attachment"])
    p.require(len(slots) == 2 and all(s.get("receipt") is None for s in slots), "two original undrained mounts")
    issued = [dict(epoch=scope["serviceEpoch"], binding=dict(store=intent["store"], container=intent["container"], launch=intent["launch"], role="runtime",
        **{k: slot[k] for k in ("volume", "attachment", "key", "mode")})) for slot in slots]
    positive, original = value["positive"], value["original"]
    for e, sequence, stage in ((positive, 1, "begun"), (original, 2, "original-root-scope-replay")):
        p.exact(e, evidence_fields | {"roots", "rootRequest"}); equal(e["arm"], arm); equal(e["scope"], scope)
        equal(e["keySHA256"], binding["key"]); equal(e["fdOperation"], "read-file-root-grant")
        equal(e["stage"], stage); p.integer(e["fdSequence"], sequence, sequence)
        equal(e["originalOperation"], dict(kind="read-file-root-grant", sequence=sequence, errorClass="transport-failed" if retired and sequence == 2 else "ok"))
        for key in ("signCount", "bytesWrittenAfterSign", "clientWrittenBytes", "clientPrefixBytes"): p.integer(e[key], 0, 0)
        for key in ("localError", "signInputSHA256", "clientPrefixSHA256"): equal(e[key], "")
        equal(e["serverDERSHA256"], server_hash if sequence == 2 else "")
        p.exact(e["roots"], {"source", "target"} | ({"replay"} if sequence == 2 else set()))
        p.exact(e["rootRequest"], {"node", "requestSequence"})
        for n in e["rootRequest"].values(): p.integer(n, U64, 1)
    roots = positive["roots"]
    for name, authority in zip(("source", "target"), issued):
        v = roots[name]; p.exact(v, {"identitySHA256", "leafSHA256", "rootRequest", "read"})
        p.pin(v["identitySHA256"]); p.pin(v["leafSHA256"])
        p.exact(v["rootRequest"], {"node", "requestSequence"})
        for n in v["rootRequest"].values(): p.integer(n, U64, 1)
        read = v["read"]; p.exact(read, {"authority", "rootNode", "node", "handle", "requestSequence", "size", "ioFlags", "contentSHA256"})
        equal(read["authority"], authority)
        for key in ("rootNode", "node", "handle", "requestSequence"): p.integer(read[key], U64, 1)
        p.integer(read["size"], 4096, 32); p.integer(read["ioFlags"], 2**32-1)
        p.require(read["ioFlags"] & ~0xe8800 == 0, "authentic readonly flags")
        p.pin(read["contentSHA256"])
        p.require(read["rootNode"] == v["rootRequest"]["node"] and read["requestSequence"] > v["rootRequest"]["requestSequence"], "original FIFO root then READ")
        equal(original["roots"][name], v)
    a, b = roots["source"], roots["target"]; ar, br = a["read"], b["read"]
    equal(a["leafSHA256"], binding["certificateSHA256"]); equal(slots[0]["attachment"], binding["targetAttachment"]); equal(slots[0]["key"], binding["key"])
    for key in ("identitySHA256", "leafSHA256"): p.require(a[key] != b[key], "distinct original mounts/leaves")
    for key in ("volume", "attachment", "key"): p.require(slots[0][key] != slots[1][key], "distinct original authorities")
    p.require(ar["contentSHA256"] != br["contentSHA256"], "exclusive distinct A/B object bytes")
    for key in ("size", "ioFlags"): equal(ar[key], br[key])
    mount_hash = p.digest(p.canonical(dict(Source=a["identitySHA256"], Target=b["identitySHA256"])))
    for e in (positive, original): equal(e["mountIdentitySHA256"], mount_hash)
    equal(positive["rootRequest"], a["rootRequest"])
    p.require(original["rootRequest"]["node"] == ar["rootNode"] and original["rootRequest"]["requestSequence"] > ar["requestSequence"], "authentic original post-positive attempt")
    for key in ("rootNode", "node", "handle"): equal(ar[key], br[key])
    p.require(br["requestSequence"] <= U64 - 2, "bounded replay FIFO")
    equal(original["roots"]["replay"], dict(source=issued[0], target=issued[1], rootNode=ar["rootNode"], node=ar["node"], handle=ar["handle"],
        rootSequence=br["requestSequence"]+1, readSequence=br["requestSequence"]+2, contentSHA256=br["contentSHA256"]))
    backing.correlate_positive(positive, baseline_ack)
    auth = value["authority"]; p.exact(auth, {"before", "atProbe", "after"} | ({"retirement"} if retired else set()))
    identity = lifecycle.comparison_identity(boot)
    for key in ("before", "atProbe", "after"): snapshot(auth[key], scope, identity)
    equal(auth["after"], auth["atProbe"])
    before, at = auth["before"], auth["atProbe"]
    for item in issued:
        bnd = item["binding"]; equal(before["attachments"][bnd["attachment"]], dict(binding=bnd, phase="ACTIVE"))
        equal(before["volume_lifecycles"][bnd["volume"]]["phase"], "READY")
    if not retired: equal(before, at)
    else:
        r = auth["retirement"]; p.exact(r, {"operation", "receipt", "queryRevision", "epoch", "controller", "attachment"})
        equal(r["operation"], slots[0]["retireOperation"]); p.uid(r["operation"])
        receipt(r["receipt"], issued[0]["binding"], at["revision"])
        p.require(r["receipt"]["revision"] > before["revision"], "advancing actual retirement receipt")
        equal(r["queryRevision"], at["revision"]); equal(r["epoch"], before["epoch"]); equal(r["controller"], before["controller"])
        equal(r["attachment"], dict(binding=issued[0]["binding"], phase="DRAINED", receipt=r["receipt"], retirement=r["operation"]))
        expected = copy.deepcopy(before); expected["revision"] = at["revision"]; expected["attachments"][slots[0]["attachment"]] = r["attachment"]
        equal(at, expected)
        query = dict(version=6, profile=p.FULL_PROFILE, requestID=binding["requestID"], armDigest=binding["armDigest"], operationUUID=binding["operationUUID"],
            caseName="same-e-existing-data", originalBootBinding=binding["boot"], original=issued[0], originalLeafSHA256=binding["certificateSHA256"], workerScope=value["service"])
        evidence = dict(stage="request-admit", errorClass="blocked", storeUUID=scope["store"], serviceEpoch=scope["serviceEpoch"], rejectedLeafSHA256=binding["certificateSHA256"],
            admission=dict(original=issued[0], **original["rootRequest"], operation="get_attr", authKind=3, noHandle=True))
        for key, state in (("worker", "observed"), ("finalized", "finalized")):
            equal(value[key], dict(query=query, state=state, selectedCount=1, evidence=evidence))
    return value


def fresh_read(value, previous, current, boot, generation, evidence_fields):
    """Sealed current-client root GETATTR+READ, released/joined, not a stat probe."""
    bounded_tree(value)
    p.exact(value, {"original", "binding", "service", "serverDERSHA256", "evidence", "released"})
    old = previous["binding"]; equal(value["original"], old)
    p.require(old["caseName"] in backing.ROOT_CASES and value["released"] is True, "released fresh root proof")
    b = value["binding"]; p.exact(b, set(old)); scope = b["scope"]; p.exact(scope, set(old["scope"]))
    for key in ("intent", "store", "serviceEpoch", "containerInstance", "launch", "prepare"): p.uid(scope[key])
    for key in ("controllerKey", "container", "specificationDigest"): p.pin(scope[key])
    p.integer(scope["controllerEpoch"], U64, 1)
    equal(scope, {k:current["id" if k == "intent" else k] for k in scope})
    p.require(current["phase"] == "running" and current["prepareCompleted"] is True, "actual fresh mounted journal")
    for key in ("store", "container", "containerInstance"): equal(scope[key], old["scope"][key])
    for key in ("intent", "serviceEpoch", "launch", "prepare"): p.require(scope[key] != old["scope"][key], "fresh launch/authority")
    p.integer(b["version"], 6, 6); equal(b["profile"], p.FULL_PROFILE); equal(b["caseName"], "cross-mount-root-grant")
    for key in ("requestID", "operationUUID", "armDigest"): equal(b[key], old[key])
    p.integer(b["generation"], U64, 1); equal(b["generation"], generation); p.require(generation != old["generation"], "actual fresh generation")
    p.exact(b["boot"], {"shimLaunchUUID", "guestBootNonce"}); p.uid(b["boot"]["guestBootNonce"])
    equal(b["boot"]["shimLaunchUUID"], scope["launch"]); p.require(b["boot"] != old["boot"], "fresh retained boot")
    ready = boot["ready"]
    equal(value["service"], {k:ready[k] for k in ("serviceEpoch", "workerUUID")}); p.uid(ready["workerUUID"])
    p.require(ready["workerUUID"] != previous["service"]["workerUUID"], "actual successor worker")
    equal(ready["storeUUID"], scope["store"])
    for key in ("serviceEpoch", "controllerEpoch", "controllerKey"): equal(ready[key], scope[key])
    equal(value["serverDERSHA256"], p.digest(bounded_base64(ready["serverDER"], 16384)))
    slots = sorted((s for s in current["slots"] if s["role"] == "runtime"), key=lambda s:s["attachment"])
    p.require(len(slots) == 2 and all(s.get("receipt") is None for s in slots), "two current undrained slots")
    for key in ("volume", "attachment", "key"): p.require(len({s[key] for s in slots}) == 2, "distinct current pair")
    equal(b["targetAttachment"], slots[0]["attachment"]); equal(b["key"], slots[0]["key"]); p.pin(b["certificateSHA256"])
    e = value["evidence"]; p.exact(e, evidence_fields | {"roots", "rootRequest"})
    equal(e["arm"], dict(version=6,profile=p.FULL_PROFILE,requestID=b["requestID"],operationUUID=b["operationUUID"],caseName=b["caseName"],
        binding=b["boot"],scope=scope,targetAttachment=b["targetAttachment"],leafSHA256=b["certificateSHA256"]))
    equal(e["scope"],scope); equal(e["keySHA256"],b["key"]); equal(e["stage"],"armed-mounted-positive")
    equal(e["fdOperation"],"read-file-root-grant"); p.integer(e["fdSequence"],1,1)
    equal(e["originalOperation"],dict(kind="read-file-root-grant",sequence=1,errorClass="ok"))
    for key in ("signCount","bytesWrittenAfterSign","clientWrittenBytes","clientPrefixBytes"): p.integer(e[key],0,0)
    for key in ("serverDERSHA256","signInputSHA256","clientPrefixSHA256","localError"): equal(e[key],"")
    p.exact(e["roots"],{"source","target"}); pair = [e["roots"][k] for k in ("source","target")]
    prior = [previous["positive"]["roots"][k] for k in ("source","target")]
    baseline = {v["volume"]:v["contentSHA256"] for v in previous["baseline"]["rootPair"]}
    equal(sorted(s["volume"] for s in slots),sorted(baseline))
    for item,slot in zip(pair,slots):
        p.exact(item,{"identitySHA256","leafSHA256","rootRequest","read"}); p.pin(item["identitySHA256"]); p.pin(item["leafSHA256"])
        p.uid(slot["volume"]); p.uid(slot["attachment"]); p.pin(slot["key"])
        p.require(all(v["leafSHA256"] != item["leafSHA256"] and v["read"]["authority"]["binding"]["attachment"] != slot["attachment"]
            and v["read"]["authority"]["binding"]["key"] != slot["key"] for v in prior), "fresh issued keys/leaves/attachments")
        root = item["rootRequest"]; p.exact(root,{"node","requestSequence"})
        for n in root.values(): p.integer(n,U64,1)
        read = item["read"]; p.exact(read,{"authority","rootNode","node","handle","requestSequence","size","ioFlags","contentSHA256"})
        equal(read["authority"],dict(epoch=scope["serviceEpoch"],binding=dict(store=scope["store"],container=scope["container"],launch=scope["launch"],role="runtime",**{k:slot[k] for k in ("volume","attachment","key","mode")})))
        p.require(slot["mode"] in ("read-only","read-write"),"actual issued mode")
        for key in ("rootNode","node","handle","requestSequence"): p.integer(read[key],U64,1)
        p.integer(read["size"],4096,32); p.integer(read["ioFlags"],2**32-1)
        p.require(read["ioFlags"] & ~0xe8800 == 0 and read["rootNode"] == root["node"] and read["requestSequence"] > root["requestSequence"],"actual FIFO root then READ")
        equal(read["contentSHA256"],baseline[slot["volume"]])
    for key in ("identitySHA256","leafSHA256"): p.require(pair[0][key] != pair[1][key],"distinct mounted identities")
    for key in ("size","ioFlags"): equal(pair[0]["read"][key],pair[1]["read"][key])
    equal(pair[0]["leafSHA256"],b["certificateSHA256"]); equal(e["rootRequest"],pair[0]["rootRequest"])
    equal(e["mountIdentitySHA256"],p.digest(p.canonical(dict(Source=pair[0]["identitySHA256"],Target=pair[1]["identitySHA256"]))))
    return value
