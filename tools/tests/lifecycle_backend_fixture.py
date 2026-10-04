"""Real private lifecycle-v2 files for engine-free backend-proof tests.

The public checkpoint is correlation metadata, never native/ROOT authority.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Tests/Compatibility"))
import storage_backend_proof as proof
from managed_prepare_lifecycle_evidence import manifest_binding


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def create_backend(root) -> Path:
    """Create an actual private owner/backing and pin root; return manifest path."""
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    root_identity = proof.capture_backend_root(root)
    owner = root / "managed-storage-owner"
    owner.mkdir(mode=0o700)
    infrastructure = root / "infrastructure"
    infrastructure.mkdir(mode=0o700, exist_ok=True)
    backing = infrastructure / "volumes.ext4"
    lease = owner / "lease"
    for path, size in ((backing, 1024 * 1024), (lease, 0)):
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.ftruncate(fd, size)
        finally:
            os.close(fd)

    def physical(path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return proof._file_identity(fd)
        finally:
            os.close(fd)

    encoded = lambda value: base64.b64encode(value).decode()
    fingerprint = lambda value: hashlib.sha256(bytes.fromhex("302a300506032b6570032100") + value).hexdigest()
    # RFC 8032 test key: public fixture material, never a production secret.
    root_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    child_key = b"c" * 32
    manifest = dict(version="storage-host-owner.v3",
        identity=dict(store=str(uuid.uuid4()), generation=1, binding=""),
        rootPublicKey=encoded(root_key), provenanceReference="a" * 64,
        root=root_identity, backing=physical(backing), directory=physical(owner), lease=physical(lease),
        bytes=backing.stat().st_size, ext4UUID=str(uuid.uuid4()))
    manifest["identity"]["binding"] = hashlib.sha256(
        b"cengine.storageauthority.binding.v3\0" + canonical(manifest_binding(manifest))).hexdigest()
    grant = dict(operation="initialize", id=str(uuid.uuid4()), identity=manifest["identity"],
        serial=1, expected_epoch=0, new_key=fingerprint(child_key))
    context = dict(serviceEpoch=str(uuid.uuid4()), controllerEpoch=1, controllerKey=grant["new_key"])
    # Swift signs Go declaration order, not the sorted checkpoint encoding.
    signing_grant = {**grant, "identity": {k: manifest["identity"][k] for k in ("store", "generation", "binding")}}
    signing_bytes = b"cengine.storageauthority.lifecycle.v2\0" + json.dumps(signing_grant, separators=(",", ":")).encode()
    with tempfile.TemporaryDirectory() as scratch:
        key, message = Path(scratch) / "key.der", Path(scratch) / "message"
        key.write_bytes(bytes.fromhex("302e020100300506032b657004220420" +
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
        key.chmod(0o600)
        message.write_bytes(signing_bytes)
        signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", str(key),
            "-in", str(message)], check=True, capture_output=True).stdout
    completed = dict(original=dict(signed=dict(grant=grant, signature=encoded(signature)),
        recipient=dict(publicKey=encoded(child_key), incarnation=str(uuid.uuid4()), daemonUniqueID=1,
            childUniqueID=2, childPID=123), requestID=str(uuid.uuid4())),
        directResult=dict(grant=grant, nonce=encoded(b"n" * 32), service_epoch=context["serviceEpoch"], revision=1))
    state = dict(version="storage-lifecycle.v2", identity=manifest["identity"], rootPublicKey=manifest["rootPublicKey"],
        provenanceReference=manifest["provenanceReference"], revision=1, current=completed, currentContext=context,
        currentService=dict(grant=grant, context=dict(service_epoch=context["serviceEpoch"], controller_epoch=1,
            controller_key=grant["new_key"]), open_revision=1, boot=dict(identity=manifest["identity"],
            service_epoch=context["serviceEpoch"], tls_root_sha256="b" * 64, server_spki="d" * 64,
            bootstrap_key=fingerprint(root_key))), observedWorker=dict(context=context, workerUUID=str(uuid.uuid4())),
        contexts=[dict(context=context, controller=completed)], serviceLinks=[], intentRevision=0, references=[],
        pendingCold=None, latestCold=None)
    for name, value in (("manifest.json", manifest), ("state.json", state)):
        fd = os.open(owner / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value))
    return owner / "manifest.json"
