"""Ordinary lifecycle-v2 DATA gates; no native PASS until attended qualification.

Uses conftest's owned Daemon, isolated root, pre-retention and cleanup. The only
daemon signal is Daemon.stop(kill=True), targeting its actual Popen child.
RTM-124/129/130/132 additionally use positively receipted, birth-fenced owned storage SIGKILL
only after workload drain/native exit. No receipt injection, runtime fault
environment, or backing-store cleanup is used.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

import pytest
from docker.types import Mount

from harness import _kernel_process, compatibility_runtime_processes, wait_for_value
import managed_storage_recovery as replacement
from storage_backend_proof import daemon_startup_mode, verify_backend
from test_upgrade_recovery import _status, _strict_shutdown
from test_volume_discovery import ALPINE, LABELS, _exec

ROOT = Path(__file__).resolve().parents[2]
FAULT_ENV = "CENGINE_COMPAT_LIFECYCLE_FAULT"
FAULT = "before-configure-v1"
REPLACEMENT_FAULT = "after-replacement-before-completion-v1"
REPLACEMENT_PAUSED = "cengine.compat.lifecycle.after-replacement-before-completion-v1.paused"
COLD_L2_FAULT = "after-cold-l2-before-a1-v1"
FIRST_COLD_COMPLETION_FAULT = "after-first-cold-completion-v1"
FIRST_COLD_COMPLETION_REACHED = "cengine.compat.lifecycle.after-first-cold-completion-v1.injected"
TAKEOVER_FAULTS = ("before-takeover-apply-v1", "after-takeover-apply-v1")
# Public, secret-free diagnostics from the compiled compatibility-only seam.
FAULT_REACHED = "cengine.compat.lifecycle.before-configure-v1.injected"
FAULT_STOPPED = "cengine.lifecycle.fresh-abort.guest-did-stop.clean"


def selected(environment, *, fault=False):
    """Only absent applicability skips; malformed/incomplete opt-ins fail closed."""
    for key in ("CENGINE_COMPAT_SHARED_STORAGE", "CENGINE_COMPAT_MANAGED_STORAGE"):
        if key in environment:
            raise ValueError(f"{key} is retired; lifecycle is the default")
    profile = environment.get(FAULT_ENV, "")
    if profile not in ("", FAULT, REPLACEMENT_FAULT, COLD_L2_FAULT, FIRST_COLD_COMPLETION_FAULT, *TAKEOVER_FAULTS):
        raise ValueError("unknown lifecycle fault profile")
    expected = FAULT if fault is True else fault
    if expected not in (False, FAULT, REPLACEMENT_FAULT, COLD_L2_FAULT, FIRST_COLD_COMPLETION_FAULT, *TAKEOVER_FAULTS):
        raise ValueError("unknown requested lifecycle fault profile")
    if any(environment.get(name) for name in (
        "CENGINE_STORAGE_LIFECYCLE_QUALIFICATION",
        "CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", "PREPARE_COMPATIBILITY_PROFILE",
    )):
        raise ValueError("ordinary lifecycle cannot combine qualification/PREPARE profiles")
    if profile and profile != expected:
        raise ValueError("lifecycle case requires its exact compiled fault profile")
    return not expected or bool(profile)


def prerequisites(environment):
    paths = {}
    for name in ("CENGINE_BINARY", "CENGINE_COMPAT_MANAGED_ASSET_DIR"):
        raw = environment.get(name, "")
        if not raw or not Path(raw).is_absolute():
            raise ValueError(f"{name} must name an explicit absolute path")
        paths[name] = Path(raw).resolve(strict=True)
    binary, assets = paths.values()
    if not assets.is_dir():
        raise ValueError("paired assets directory is missing")
    for executable in (binary, binary.with_name("cengine-storage-controller"),
                       binary.with_name("cengine-helper")):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("paired signed compatibility executable is missing")
    for key, name in (("CENGINE_KERNEL", "vmlinux"),
                      ("CENGINE_CONTAINER_INITRAMFS", "container-initramfs.cpio.gz"),
                      ("CENGINE_STORAGE_INITRAMFS", "storage-initramfs.cpio.gz")):
        if not (assets / name).is_file() or Path(environment.get(key, "")).resolve() != assets / name:
            raise ValueError("daemon assets do not match the paired asset directory")
    if not environment.get("CENGINE_DEVELOPER_ID_APPLICATION", "").startswith("Developer ID Application: "):
        raise ValueError("signed Developer ID compatibility runner required")
    # Read-only normal guards, never install, build, download or elevate here.
    subprocess.run(["python3", str(ROOT / "Scripts/check-managed-guest-assets.py"), str(assets)],
                   check=True, capture_output=True, timeout=60)
    subprocess.run([
        "/bin/sh", "-ec",
        'ROOT=$1; . "$ROOT/Scripts/compat-network-helper.sh"; '
        '. "$1/Scripts/managed-signing.sh"; '
        'team=$(managed_signing_team "$3"); '
        'managed_signing_verify "$2" dev.cengine.engine.test-compat "$team"; '
        'managed_signing_verify "$(dirname "$2")/cengine-storage-controller" dev.cengine.storage-control.test-compat "$team"; '
        'managed_signing_verify "$(dirname "$2")/cengine-helper" dev.cengine.network-helper.test-compat "$team"; '
        'fingerprint=$("$1/Scripts/network-helper-fingerprint.sh"); '
        'compat_network_helper_require "$2" "$fingerprint"',
        "lifecycle-prerequisites", str(ROOT), str(binary), environment["CENGINE_DEVELOPER_ID_APPLICATION"],
    ], check=True, capture_output=True, timeout=60)


@pytest.fixture
def image_cache(image_cache, request):
    case = request.node.get_closest_marker("compat").args
    fault = {("RTM-119",): FAULT, ("RTM-121",): REPLACEMENT_FAULT, ("RTM-129",): COLD_L2_FAULT,
             ("RTM-130",): COLD_L2_FAULT, ("RTM-132",): FIRST_COLD_COMPLETION_FAULT}.get(case, False)
    if case == ("RTM-125",):
        fault = os.environ.get(FAULT_ENV) or TAKEOVER_FAULTS[0]
        if fault not in TAKEOVER_FAULTS:
            raise ValueError("RTM-125 requires an exact sealed takeover profile")
    if not selected(os.environ, fault=fault):
        pytest.skip("requires compiled lifecycle fault profile" if fault else
                    "requires ordinary signed lifecycle runner")
    try:
        prerequisites(os.environ)
    except (OSError, ValueError, subprocess.SubprocessError):
        pytest.fail("lifecycle prerequisites incomplete; use installed paired helper/assets", pytrace=False)
    return image_cache


@pytest.fixture
def daemon(daemon, request):
    # Override the owned fixture, not its ownership/signing/retention guards.
    # Complete both startup attempts before autouse fixtures request the API.
    if request.node.get_closest_marker("compat").args == ("RTM-119",):
        resume_initialization(daemon)
    return daemon


@pytest.fixture
def shared(client, daemon):
    assert daemon_startup_mode(daemon) == "lifecycle"
    assert daemon.root_retained, "managed fixture must pre-retain this owned root"
    volume = client.volumes.create("lifecycle-" + uuid.uuid4().hex, labels=LABELS)
    # Deliberately leave resource cleanup to the owned Daemon fixture. Failed
    # evidence is retained rather than altered by container/volume deletion.
    return volume


def create_peer(client, volume, suffix, command=None):
    return client.containers.create(
        ALPINE, command or ["sleep", "600"], name=volume.name + "-" + suffix,
        labels=LABELS, network_mode="none", restart_policy={"Name": "no"},
        mounts=[Mount("/data", volume.name, type="volume", no_copy=True)],
    )


def mount_proof(daemon, container):
    proof = verify_backend(daemon.root, "shared", _exec(container, "cat", "/proc/self/mountinfo").decode(),
                           startup_mode=daemon_startup_mode(daemon))
    assert proof["mode"] == "lifecycle"
    return proof


def exchange(left, right, marker):
    # New bytes in BOTH directions, not merely a persisted seed or cached read.
    for writer, reader, suffix in ((left, right, "left"), (right, left, "right")):
        payload = marker + "-" + suffix
        _exec(writer, "sh", "-ec", f"printf '%s' '{payload}' > /data/{suffix}; sync")
        assert _exec(reader, "cat", "/data/" + suffix) == payload.encode()


def native_snapshot(daemon, container_ids):
    result = {}
    for process in compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)):
        args = process.arguments
        if len(args) < 2 or args[1] != "vm-shim":
            continue
        assert process.identity is not None and process.pidversion is not None
        assert args.count("--spec") == 1
        path = Path(args[args.index("--spec") + 1]).resolve(strict=True)
        assert path.is_relative_to(daemon.root.resolve())
        specification = json.loads(path.read_bytes())
        key = "storage" if specification["kind"] == "storage" else specification["containerID"]
        if key != "storage" and key not in container_ids:
            continue
        assert key not in result
        status = _status(specification)
        assert status["state"] == "running"
        assert status["processIdentifier"] == process.pid
        for field in ("processStartTime", "executableUUID", "shimLaunchUUID", "generation"):
            assert status.get(field), "missing native shim identity"
        if key == "storage":
            replacement.require("storageStartupMode" not in specification, "retired storage startup selector")
            assert specification["containerID"] == "cengine-storage"
            assert args[-4:] == ("--storage-disk-fd", "3", "--storage-lifecycle-fd", "4")
        result[key] = {
            "native": (process.pid, process.identity, process.pidversion),
            "status": {key: status[key] for key in (
                "processIdentifier", "processStartTime", "executableUUID", "shimLaunchUUID", "generation")},
            # Never put the shim token into assertion diagnostics.
            "specification": {"outputSpool": specification.get("outputSpool"),
                              "sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
        }
    assert set(result) == {"storage", *container_ids}, "missing original storage/workload VM"
    return result


def progress_command(name, peer):
    # FD3 opens ONCE, then its pathname is unlinked. Continued writes to that
    # inode cannot be imitated by reopening the old name after daemon recovery.
    return ["sh", "-ec", f"""
exec 3>/data/{name}.open
rm /data/{name}.open
identity=$(stat -Lc '%d:%i' /proc/$$/fd/3)
i=0
while test "$i" -lt 600; do
    i=$((i+1))
    printf '%s\\n' "$i" >&3
    printf '%s\\n' "$i" > /data/{name}.tmp
    mv /data/{name}.tmp /data/{name}.progress
    other=0
    if test -f /data/{peer}.progress; then other=$(cat /data/{peer}.progress); fi
    sync
    position=$(sed -n 's/^pos:[[:space:]]*//p' /proc/$$/fdinfo/3)
    uptime=$(cut -d. -f1 /proc/uptime)
    printf 'LIFECYCLE {name} %s %s %s %s %s\\n' "$i" "$other" "$identity" "$position" "$uptime"
    sleep 1
done
exit 97
"""]


def parse_progress(data, name):
    pattern = rb"LIFECYCLE " + name.encode() + rb" ([1-9][0-9]*) ([0-9]+) ([0-9]+:[1-9][0-9]*) ([1-9][0-9]*) ([0-9]+)\n"
    rows = list(re.finditer(pattern, data))
    if not rows:
        return None
    row = rows[-1]
    return (int(row[1]), int(row[2]), row[3].decode(), int(row[4]), int(row[5]))


def spool_progress(daemon, snapshot, name):
    spool = snapshot["specification"]["outputSpool"]
    directory = Path(spool["directoryPath"]).resolve(strict=True)
    assert directory.is_relative_to(daemon.root.resolve())
    info = directory.stat()
    assert (info.st_dev, info.st_ino) == (spool["directoryIdentity"]["device"], spool["directoryIdentity"]["inode"])
    directory /= "stdout.spool"
    info = directory.stat()
    expected = spool["stdoutSpoolDirectoryIdentity"]
    assert (info.st_dev, info.st_ino) == (expected["device"], expected["inode"])
    # This bounded workload emits far less than one segment. Read only data files,
    # never cursor/private metadata; no daemon or Docker API participates.
    files = list(directory.glob("*.data"))
    assert 1 <= spool["maximumSegments"] and len(files) <= spool["maximumSegments"]
    assert all(re.fullmatch(r"(?:active-[0-9]+|segment-[0-9]+-[0-9]+)\.data", path.name)
               for path in files), "unknown output spool data name"
    data = bytearray()
    for path in sorted(files, key=lambda path: int(path.name.split("-")[1].split(".")[0])):
        with path.open("rb") as stream:
            chunk = stream.read(262145)
        assert len(chunk) <= 262144
        data.extend(chunk)
        assert len(data) <= 262144
    return parse_progress(bytes(data), name)


def progressed(before, after):
    return (before is not None and after is not None and after[0] > before[0] + 1
            and after[1] > before[1] + 1 and after[2] == before[2] and after[3] > before[3])


def produced_while_absent(row, clock, killed_at):
    return row is not None and row[4] > clock[1] + killed_at - clock[0] + 1


@pytest.mark.compat("RTM-117")
def test_lifecycle_v2_fresh_shared_fuse_data(client, daemon, shared):
    peers = [create_peer(client, shared, name) for name in ("left", "right")]
    # Both references must exist before FIRST start; otherwise direct ext4 can win.
    for peer in peers:
        peer.start()
        mount_proof(daemon, peer)
    native_snapshot(daemon, {peer.id for peer in peers})
    exchange(peers[0], peers[1], "fresh-" + uuid.uuid4().hex)


@pytest.mark.compat("RTM-122")
@pytest.mark.parametrize("daemon", ["lifecycle-root-permissions"], indirect=True)
def test_lifecycle_v2_repairs_owned_root_permissions(client, daemon, shared):
    # The owned fixture deliberately starts from 0755. No test-side repair.
    assert daemon.root.stat().st_mode & 0o7777 == 0o700
    peers = [create_peer(client, shared, name) for name in ("left", "right")]
    for peer in peers:
        peer.start()
        mount_proof(daemon, peer)
    native_snapshot(daemon, {peer.id for peer in peers})
    exchange(peers[0], peers[1], "permissions-" + uuid.uuid4().hex)
    original = native_snapshot(daemon, {peer.id for peer in peers})
    # Repeat on a populated current-format store, not just an empty root.
    daemon.stop(kill=True)
    # The RTM-122 fixture re-injects 0755 after its strict pre-spawn root pin.
    daemon.start()
    assert daemon.root.stat().st_mode & 0o7777 == 0o700
    assert native_snapshot(daemon, {peer.id for peer in peers}) == original
    exchange(peers[0], peers[1], "existing-permissions-" + uuid.uuid4().hex)


@pytest.mark.compat("RTM-123")
def test_lifecycle_v2_storage_shim_owns_process_group(client, daemon, shared):
    peers = [create_peer(client, shared, name) for name in ("left", "right")]
    for peer in peers:
        peer.start()
        mount_proof(daemon, peer)
    original = native_snapshot(daemon, {peer.id for peer in peers})
    storage_pid = original["storage"]["native"][0]
    # launchd cleans up the daemon's process group after it exits. This kernel
    # property catches raw-posix_spawn inheritance even in the isolated harness.
    assert os.getpgid(storage_pid) == storage_pid
    assert os.getpgid(storage_pid) != os.getpgid(daemon.process.pid)
    exchange(peers[0], peers[1], "before-graceful-" + uuid.uuid4().hex)
    daemon.stop()
    assert daemon.process.returncode == 0, "graceful stop must not fall back to SIGKILL"
    assert native_snapshot(daemon, {peer.id for peer in peers}) == original
    daemon.start()
    assert client.ping()
    assert native_snapshot(daemon, {peer.id for peer in peers}) == original
    for peer in peers:
        peer.reload()
        assert peer.status == "running" and peer.attrs["RestartCount"] == 0
        mount_proof(daemon, peer)
    exchange(peers[0], peers[1], "after-graceful-" + uuid.uuid4().hex)


@pytest.mark.compat("RTM-127")
def test_lifecycle_v2_ready_graceful_restarts(client, daemon, shared):
    """SIGTERM immediately after readiness must exit cleanly, never use a kill fallback."""
    peers = [create_peer(client, shared, side) for side in ("left", "right")]
    for peer in peers:
        peer.start()
        mount_proof(daemon, peer)
    ids = {peer.id for peer in peers}
    original = native_snapshot(daemon, ids)
    exchange(*peers, "ready-stop-seed-" + uuid.uuid4().hex)
    daemon.stop()
    assert daemon.process.returncode == 0
    for _ in range(3):
        daemon.start()
        # No extra API call, sleep, or native inspection between ready and SIGTERM.
        # Wait on the exact Popen child; unlike Daemon.stop this never escalates.
        daemon.process.terminate()
        assert daemon.process.wait(timeout=15) == 0
        daemon.stop()  # Close the already-exited child's log, not a second signal.
        assert native_snapshot(daemon, ids) == original
    daemon.start()
    assert client.ping() and native_snapshot(daemon, ids) == original
    for peer in peers:
        peer.reload()
        assert peer.status == "running" and peer.attrs["RestartCount"] == 0
        mount_proof(daemon, peer)
    exchange(*peers, "ready-stop-recovered-" + uuid.uuid4().hex)


@pytest.mark.compat("RTM-118")
def test_lifecycle_v2_daemon_restart_preserves_live_data(client, daemon, shared):
    names = ("left", "right")
    peers = [create_peer(client, shared, name, progress_command(name, other))
             for name, other in zip(names, reversed(names))]
    for peer in peers:
        peer.start()
        mount_proof(daemon, peer)
    original = native_snapshot(daemon, {peer.id for peer in peers})
    baseline = {}
    for name, peer in zip(names, peers):
        baseline[name] = wait_for_value(
            lambda: parse_progress(peer.logs(), name),
            lambda row: row is not None and row[1] > 1, timeout=30,
            description="both peers exchanging shared DATA through original FD3")
    # Bound the Guest clock at kill from a direct current /proc read, not a
    # possibly buffered log. Host elapsed time overestimates the interval from
    # the actual Guest sample to waitpid. Later Guest timestamps therefore prove
    # production AFTER death, even if the shim had an arbitrary output backlog.
    clocks = {}
    for name, peer in zip(names, peers):
        sampled_at = time.monotonic()
        uptime = float(_exec(peer, "cat", "/proc/uptime").split()[0])
        clocks[name] = (sampled_at, uptime)
    daemon.stop(kill=True)
    killed_at = time.monotonic()
    assert daemon.process.poll() == -9
    # Establish a NEW baseline after waitpid. Two further peer read/write cycles
    # on both sides avoid accepting buffered output emitted before the kill.
    absent = {}
    for name, peer in zip(names, peers):
        observation = original[peer.id]
        first = wait_for_value(lambda: spool_progress(daemon, observation, name),
                               lambda row: row is not None, timeout=15,
                               description="owned workload spool while daemon is absent")
        absent[name] = wait_for_value(
            lambda: spool_progress(daemon, observation, name),
            lambda row: progressed(first, row) and progressed(baseline[name], row)
            and produced_while_absent(row, clocks[name], killed_at),
            timeout=30, description="new bidirectional DATA and original unlinked FD progress without daemon")
    assert daemon.process.poll() == -9
    assert native_snapshot(daemon, {peer.id for peer in peers}) == original
    daemon.start()
    assert client.ping()
    assert native_snapshot(daemon, {peer.id for peer in peers}) == original
    for name, peer in zip(names, peers):
        peer.reload()
        assert peer.status == "running" and peer.attrs["RestartCount"] == 0
        mount_proof(daemon, peer)
        wait_for_value(lambda: parse_progress(peer.logs(), name),
                       lambda row: progressed(absent[name], row), timeout=30,
                       description="original unlinked FD continues after control reattachment")
    exchange(peers[0], peers[1], "reattached-" + uuid.uuid4().hex)
    fresh = create_peer(client, shared, "fresh")
    fresh.start()
    mount_proof(daemon, fresh)
    exchange(peers[0], fresh, "fresh-attachment-" + uuid.uuid4().hex)


def disk_identity(root):
    path = root / "infrastructure/volumes.ext4"
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        stream.seek(1024)
        superblock = stream.read(1024)
    assert len(superblock) == 1024 and superblock[56:58] == b"\x53\xef"
    # UUID plus filesystem creation time reject a same-path/same-inode reformat.
    return (info.st_dev, info.st_ino, info.st_size, superblock[104:120], superblock[264:268])


def lifecycle_owner(record):
    """Strict public v2 correlation only; never signature/stop authority."""
    assert record["version"] == "storage-lifecycle.v2"
    assert type(record["revision"]) is int and record["revision"] > 0
    # adoptionRetry survives completed adoption; it is retry metadata, not an
    # unfinished-operation flag (ManagedStorageLifecycleCheckpoint.stageColdRequest).
    for field in ("pending", "pendingService", "pendingTakeover", "pendingCold",
                  "sealed", "terminal"):
        assert record.get(field) is None, "unsettled lifecycle owner"
    identity = record["identity"]
    assert set(identity) == {"store", "generation", "binding"}
    replacement.uuid4(identity["store"])
    assert type(identity["generation"]) is int and identity["generation"] > 0
    service = record["currentService"]
    boot, context = service["boot"], service["context"]
    assert type(service["open_revision"]) is int and service["open_revision"] > 0
    assert set(boot) == {"identity", "service_epoch", "tls_root_sha256",
                         "server_spki", "bootstrap_key"}
    assert set(context) == {"service_epoch", "controller_epoch", "controller_key"}
    assert boot["identity"] == service["grant"]["identity"] == identity
    assert boot["service_epoch"] == context["service_epoch"]
    for value in (identity["binding"], boot["tls_root_sha256"], boot["server_spki"],
                  boot["bootstrap_key"], context["controller_key"]):
        assert isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
    replacement.uuid4(boot["service_epoch"])
    assert type(context["controller_epoch"]) is int and context["controller_epoch"] > 0
    assert context["controller_key"] == service["grant"]["new_key"]
    assert context["controller_epoch"] == service["grant"]["expected_epoch"] + 1
    # Optional in the general checkpoint schema, required for settled RTM-120.
    # HOST emits this only after a fresh ROOT match to actual boot readiness and
    # physical intent census. It is evidence, not native/API authorization.
    observation = record.get("observedWorker")
    assert type(observation) is dict and set(observation) == {"context", "workerUUID"}
    expected_context = {
        "serviceEpoch": context["service_epoch"], "controllerEpoch": context["controller_epoch"],
        "controllerKey": context["controller_key"]}
    for projected in (record["currentContext"], observation["context"]):
        assert type(projected) is dict and set(projected) == set(expected_context)
        assert type(projected["controllerEpoch"]) is int
        assert projected == expected_context, "stale or mismatched worker observation context"
    replacement.uuid4(observation["workerUUID"])
    assert isinstance(record["rootPublicKey"], str) and record["rootPublicKey"]
    return {"serviceEpoch": boot["service_epoch"], "workerUUID": observation["workerUUID"]}


def changed_gzip_mtime(original):
    """Change only RFC 1952 MTIME, never recompress or patch Guest code."""
    if len(original) < 18 or original[:3] != b"\x1f\x8b\x08" or original[3] & 0xe2:
        raise ValueError("requires gzip/deflate without FHCRC or reserved flags")
    timestamp = (int.from_bytes(original[4:8], "little") + 1) % (1 << 32)
    updated = original[:4] + timestamp.to_bytes(4, "little") + original[8:]
    assert updated != original and gzip.decompress(updated) == gzip.decompress(original)
    return updated


def stage_guest_update(source, destination):
    """Keep genuine ordinary provenance; update only the compressed artifact digest."""
    def assert_current(directory):
        subprocess.run([
            sys.executable, "-c",
            "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
            "from guest_asset_provenance import assert_current; "
            "assert_current(Path(sys.argv[2]), Path(sys.argv[3]))",
            str(ROOT / "Scripts"), str(ROOT), str(directory),
        ], check=True, capture_output=True, timeout=120)

    assert_current(source)
    names = ("vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz", "disk-bootstrap.json")
    original = {name: (source / name).read_bytes() for name in names}
    updated = dict(original)
    updated["storage-initramfs.cpio.gz"] = changed_gzip_mtime(original["storage-initramfs.cpio.gz"])
    metadata = json.loads(original["disk-bootstrap.json"])
    digest = hashlib.sha256(updated["storage-initramfs.cpio.gz"]).hexdigest()
    assert digest != metadata["storageInitramfsSHA256"]
    metadata["storageInitramfsSHA256"] = digest
    updated["disk-bootstrap.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    destination.mkdir(mode=0o700)  # New paired directory only; never overwrite installed assets.
    for name, data in updated.items():
        (destination / name).write_bytes(data)
    (destination / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(updated[name]).hexdigest()}  {name}\n" for name in names))
    assert_current(destination)
    assert all((source / name).read_bytes() == data for name, data in original.items())
    assert metadata["ordinaryProvenance"] == json.loads(original["disk-bootstrap.json"])["ordinaryProvenance"]
    return digest


def storage_launch_history(root):
    directory = root / "infrastructure/storage-shim-generations"
    history = {path.relative_to(directory): path.read_bytes()
               for path in directory.rglob("*") if path.is_file()}
    assert history and all(path.name in ("spec.json", "intent.json", "launch.json") for path in history)
    return history


def storage_guest_proof(daemon, native, digest):
    raw = (daemon.root / "infrastructure/shim.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == native["storage"]["specification"]["sha256"]
    specification = json.loads(raw)
    assert specification["expectedInitramfsSHA256"] == digest
    assert Path(specification["initialRamdiskPath"]).resolve() == daemon.storage_initramfs.resolve()
    return specification


@pytest.mark.compat("RTM-128")
def test_lifecycle_v2_two_strict_cold_restarts_with_live_peers(client, daemon, shared):
    strict_cold_restarts(client, daemon, shared, cycles=2)


@pytest.mark.compat("RTM-131")
def test_lifecycle_v2_cold_enrollment_survives_live_reattachment(client, daemon, shared):
    """Cold enrollment must finish with a retained ROOT channel, not merely L3."""
    strict_cold_restarts(client, daemon, shared, cycles=1, live_reattachment=True)


@pytest.mark.compat("RTM-133")
def test_lifecycle_v2_retained_history_allows_live_storage_control(client, daemon, shared):
    """Revalidate immutable predecessor histories during ordinary storage IPC.

    Prior-boot unreadable-PID classification is covered by native Swift seams;
    this VM case does not manufacture boot IDs or rewrite launch records.
    """
    strict_cold_restarts(client, daemon, shared, cycles=2, live_reattachment=True,
                        history_revalidation=True)


def revalidate_storage_history(client, daemon, ids, expected, history):
    # Network CRUD drives the engine's authenticated configureFabric storage IPC,
    # whose peer validation must scan every retained storage launch generation.
    network = client.networks.create("cold-history-" + uuid.uuid4().hex,
                                     driver="bridge", internal=True)
    try:
        assert native_snapshot(daemon, ids) == expected
        assert storage_launch_history(daemon.root) == history
    finally:
        network.remove()
    assert native_snapshot(daemon, ids) == expected
    assert storage_launch_history(daemon.root) == history


def strict_cold_restarts(client, daemon, shared, *, cycles, live_reattachment=False,
                         history_revalidation=False):
    """Supported cold shutdown, not daemon-only live restore or forced cleanup."""
    from test_managed_storage_recovery import parent_deadline

    with parent_deadline(time.monotonic() + 420):
        peers = [create_peer(client, shared, side) for side in ("left", "right")]
        for peer in peers:
            peer.update(restart_policy={"Name": "always"})
            peer.start()
            peer.reload()
            assert peer.status == "running" and peer.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"
            mount_proof(daemon, peer)
        ids = {peer.id for peer in peers}
        seed = "strict-cold-seed-" + uuid.uuid4().hex
        exchange(*peers, seed)
        for peer, side in zip(peers, ("left", "right")):
            _exec(peer, "sh", "-ec", f"cp /data/{side} /data/seed-{side}; sync")
        disk = disk_identity(daemon.root)
        initial, _, _ = replacement.lifecycle_owner(daemon.root)
        manifest = initial["manifest"]
        before = initial["checkpoint"]
        lifecycle_owner(before)

        for cycle in range(cycles):
            history = storage_launch_history(daemon.root) if history_revalidation else None
            for peer in peers:
                peer.reload()
                assert peer.status == "running", "strict shutdown must begin with LIVE retained peers"
            native = native_snapshot(daemon, ids)
            census = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
            targets = [next(p for p in census if p.pid == row["native"][0]) for row in native.values()]
            # Graceful daemon exit is separate from the supported cold command.
            # Wait on this exact child with no Daemon.stop escalation path.
            daemon.process.terminate()
            assert daemon.process.wait(timeout=15) == 0
            daemon.stop()  # Already exited: close its log only; never signal here.
            assert native_snapshot(daemon, ids) == native
            _strict_shutdown(daemon)
            for target in targets:
                wait_for_value(lambda: replacement.exact_exit(target, _kernel_process(target.pid)),
                               bool, timeout=30, description="strict shutdown native birth ended")
            assert not compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
            assert disk_identity(daemon.root) == disk
            daemon.start()
            assert client.ping()

            def running():
                for peer in peers:
                    peer.reload()
                return all(peer.status == "running" and peer.attrs["State"]["Running"] for peer in peers)

            wait_for_value(running, bool, timeout=120, description="automatic always-policy cold restart")
            assert {peer.id for peer in client.containers.list(all=True) if peer.id in ids} == ids
            fresh = native_snapshot(daemon, ids)
            for key in native:
                assert fresh[key]["native"][1] != native[key]["native"][1], "new native birth required"
                assert fresh[key]["status"]["shimLaunchUUID"] != native[key]["status"]["shimLaunchUUID"]
            after_record, _, _ = replacement.lifecycle_owner(daemon.root)
            after = after_record["checkpoint"]
            old, new = lifecycle_owner(before), lifecycle_owner(after)
            assert after_record["manifest"] == manifest
            assert after["identity"] == initial["checkpoint"]["identity"]
            assert after["rootPublicKey"] == initial["checkpoint"]["rootPublicKey"]
            assert after["currentContext"]["controllerEpoch"] == before["currentContext"]["controllerEpoch"] + 1
            assert new["serviceEpoch"] != old["serviceEpoch"] and new["workerUUID"] != old["workerUUID"]
            assert after["currentContext"]["controllerKey"] != before["currentContext"]["controllerKey"]
            assert disk_identity(daemon.root) == disk
            for peer in peers:
                assert peer.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"
                mount_proof(daemon, peer)
                for side in ("left", "right"):
                    assert _exec(peer, "cat", "/data/seed-" + side) == (seed + "-" + side).encode()
            exchange(*peers, f"strict-cold-{cycle}-" + uuid.uuid4().hex)
            if history_revalidation:
                retained = storage_launch_history(daemon.root)
                assert all(retained.get(path) == data for path, data in history.items())
                generation = Path(fresh["storage"]["status"]["shimLaunchUUID"])
                assert set(retained) - set(history) == {
                    generation / name for name in ("spec.json", "intent.json", "launch.json")}
                revalidate_storage_history(client, daemon, ids, fresh, retained)
            before = after

        if live_reattachment:
            native = native_snapshot(daemon, ids)
            restart_counts = {peer.id: peer.attrs["RestartCount"] for peer in peers}
            daemon.process.terminate()
            assert daemon.process.wait(timeout=15) == 0
            daemon.stop()  # Reap only; no fallback signal.
            assert native_snapshot(daemon, ids) == native
            daemon.start()
            assert client.ping()
            assert native_snapshot(daemon, ids) == native
            attached, _, _ = replacement.lifecycle_owner(daemon.root)
            old, new = lifecycle_owner(before), lifecycle_owner(attached["checkpoint"])
            assert attached["manifest"] == manifest and disk_identity(daemon.root) == disk
            assert new["serviceEpoch"] == old["serviceEpoch"] and new["workerUUID"] == old["workerUUID"]
            assert attached["checkpoint"]["identity"] == before["identity"]
            assert attached["checkpoint"]["rootPublicKey"] == before["rootPublicKey"]
            assert attached["checkpoint"]["currentContext"]["controllerEpoch"] == before["currentContext"]["controllerEpoch"] + 1
            for peer in peers:
                peer.reload()
                assert peer.status == "running" and peer.attrs["RestartCount"] == restart_counts[peer.id]
                mount_proof(daemon, peer)
                for side in ("left", "right"):
                    assert _exec(peer, "cat", "/data/seed-" + side) == (seed + "-" + side).encode()
            exchange(*peers, "cold-enrollment-reattached-" + uuid.uuid4().hex)
            if history_revalidation:
                assert storage_launch_history(daemon.root) == retained
                revalidate_storage_history(client, daemon, ids, native, retained)


def cold_signed_digest(signed):
    return hashlib.sha256(b"cengine.storage-lifecycle-cold-root.signed-open.v1\0" +
                          json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def cold_predecessor(service):
    context = service["context"]
    return dict(current_grant=service["grant"], service_epoch=context["service_epoch"],
                controller_epoch=context["controller_epoch"], controller_key=context["controller_key"],
                open_revision=service["open_revision"], bootstrap_key=service["boot"]["bootstrap_key"])


def frozen_cold_proof(before, frozen):
    """HOST attempted metadata is correlation, NOT evidence that ROOT reached L2."""
    lifecycle_owner(before)
    assert frozen["revision"] > before["revision"]
    for field in ("identity", "rootPublicKey", "provenanceReference", "current", "currentContext", "currentService", "latestCold"):
        assert frozen.get(field) == before.get(field), "failed cold must keep committed C1"
    for field in ("pending", "pendingService", "pendingTakeover", "resolvedDeadCold", "sealed", "terminal"):
        assert frozen.get(field) is None
    pending = frozen["pendingCold"]
    assert pending["bootAttempted"] is True and pending.get("resolutionRequest") is None
    request, prepared = pending["request"], pending["prepared"]
    assert prepared.get("recoveryBridge") is None
    prepare, signed = request["prepare"], prepared["signedOpen"]
    opened = signed["request"]
    assert opened["operation_id"] == prepare["operationID"] == opened["takeover"]["grant"]["id"]
    assert opened["predecessor"] == prepare["expectedPredecessor"] == cold_predecessor(before["currentService"])
    assert prepare["identity"] == opened["takeover"]["grant"]["identity"] == before["identity"]
    assert opened["launch"] == prepare["mountedGreeting"]["launch"]
    assert prepared["baseEpoch"] == prepare["expectedAllocatedEpoch"] + 1
    assert opened["takeover"]["grant"]["expected_epoch"] == before["currentContext"]["controllerEpoch"]
    assert opened["takeover"]["grant"]["new_key"] != before["currentContext"]["controllerKey"]
    for field in ("prepareRequestID", "completionRequestID"):
        replacement.uuid4(request[field])
    assert request["prepareRequestID"] != request["completionRequestID"]
    from managed_prepare_lifecycle_evidence import encoded
    encoded(signed["signature"], 64)
    encoded(opened["takeover"]["signature"], 64)
    return pending


def recovered_cold_proof(before, frozen, after):
    """ROOT-authenticated resolution of the exact frozen attempt supplies L2 evidence.

    Combined with the sealed helper's post-L2/pre-A1 callsite (source guards),
    this is a real protected cut, not an inference from HOSTauthorizeCold.
    """
    pending = frozen_cold_proof(before, frozen)
    lifecycle_owner(after)
    assert after.get("resolvedDeadCold") is None and after["revision"] > frozen["revision"]
    for field in ("identity", "rootPublicKey", "provenanceReference"):
        assert after[field] == before[field]
    cold = after["latestCold"]
    dead, completion = cold["deadPredecessor"], cold["completion"]
    attempted = dict(dead["attempted"])
    resolution = attempted.pop("resolutionRequest")
    original = dict(pending)
    original.pop("resolutionRequest", None)
    assert attempted == original, "all frozen request IDs, signatures and launch digests must survive"
    bridge = dead["value"]
    assert resolution["value"] == bridge["request"]
    replacement.uuid4(resolution["requestID"])
    assert resolution["requestID"] not in (pending["request"]["prepareRequestID"], pending["request"]["completionRequestID"])
    assert bridge == cold["prepared"]["recoveryBridge"] == completion["recoveryBridge"]
    assert dead["anchor"]["controller"] == before["current"]
    assert dead["anchor"]["context"] == before["currentContext"]
    assert dead["anchorService"] == bridge["anchor"] == before["currentService"]
    signed = pending["prepared"]["signedOpen"]
    request = bridge["request"]
    assert request["identity"] == before["identity"]
    assert request["operationID"] == signed["request"]["operation_id"]
    assert request["signedOpenSHA256"] == cold_signed_digest(signed)
    replacement.uuid4(request["resolutionID"])
    assert request["resolutionID"] != request["operationID"]
    assert bridge["successorOrigin"] == pending["prepared"]["successorOrigin"]
    assert bridge["baseEpoch"] == pending["prepared"]["baseEpoch"]
    assert bridge["receipt"]["grant"] == signed["request"]["takeover"]["grant"] == bridge["successor"]["grant"]
    assert bridge["receipt"]["service_epoch"] == bridge["successor"]["context"]["service_epoch"]
    assert bridge["receipt"]["revision"] == bridge["successor"]["open_revision"]
    assert cold["predecessorService"] == bridge["successor"]
    predecessor = cold["predecessor"]["controller"]
    assert predecessor["original"]["signed"] == signed["request"]["takeover"]
    assert predecessor["original"]["recipient"] == pending["request"]["recipient"]
    assert predecessor["original"]["requestID"] == pending["request"]["completionRequestID"]
    assert predecessor["directResult"] == bridge["receipt"]
    fresh = cold["prepared"]["signedOpen"]
    assert fresh["request"]["predecessor"] == cold["request"]["prepare"]["expectedPredecessor"] == cold_predecessor(bridge["successor"])
    assert completion["operationID"] == fresh["request"]["operation_id"] == cold["request"]["prepare"]["operationID"]
    assert completion["operationID"] not in (request["operationID"], request["resolutionID"])
    assert completion["signedOpenSHA256"] == cold_signed_digest(fresh)
    assert completion["baseEpoch"] == cold["prepared"]["baseEpoch"] == bridge["baseEpoch"] + 1
    assert completion["successorOrigin"] == cold["prepared"]["successorOrigin"]
    assert completion["successorOrigin"]["rootPublicKey"] == bridge["successorOrigin"]["rootPublicKey"] == before["rootPublicKey"]
    assert completion["successorOrigin"]["binding"] == bridge["successorOrigin"]["binding"]
    assert completion["successorOrigin"]["shimLaunchUUID"] != bridge["successorOrigin"]["shimLaunchUUID"]
    assert completion["receipt"]["grant"] == fresh["request"]["takeover"]["grant"] == after["currentService"]["grant"]
    assert completion["successor"] == after["currentService"]
    assert after["current"]["original"]["signed"] == fresh["request"]["takeover"]
    assert after["current"]["original"]["requestID"] == cold["request"]["completionRequestID"]
    assert after["current"]["directResult"] == completion["receipt"]
    assert predecessor["original"]["serviceEpoch"] == bridge["receipt"]["service_epoch"]
    assert after["current"]["original"]["recipient"] == cold["request"]["recipient"]
    assert after["current"]["original"]["serviceEpoch"] == completion["receipt"]["service_epoch"]
    assert completion["receipt"]["service_epoch"] == after["currentContext"]["serviceEpoch"]
    assert completion["receipt"]["revision"] == after["currentService"]["open_revision"]
    services = (before["currentService"], bridge["successor"], after["currentService"])
    for field in ("controller_key", "service_epoch"):
        assert len({service["context"][field] for service in services}) == 3
    for old, new in zip(services, services[1:]):
        assert new["context"]["controller_epoch"] == old["context"]["controller_epoch"] + 1
        assert new["open_revision"] > old["open_revision"]
        assert new["grant"]["serial"] > old["grant"]["serial"]
        for field in ("controller_key", "service_epoch"):
            assert new["context"][field] != old["context"][field]
        for field in ("tls_root_sha256", "server_spki"):
            assert new["boot"][field] != old["boot"][field]
    assert after["observedWorker"]["workerUUID"] != before["observedWorker"]["workerUUID"]


def committed_cold_edge(before, after):
    """Exact public L3 correlation, without assuming post-completion enrollment."""
    assert after["version"] == before["version"] == "storage-lifecycle.v2"
    assert after["revision"] > before["revision"]
    for field in ("identity", "rootPublicKey", "provenanceReference"):
        assert after[field] == before[field]
    for field in ("pending", "pendingService", "pendingTakeover", "pendingCold", "resolvedDeadCold", "sealed", "terminal"):
        assert after.get(field) is None, "unsettled committed cold owner"
    cold = after["latestCold"]
    request, prepared, completion = cold["request"], cold["prepared"], cold["completion"]
    assert cold.get("deadPredecessor") is None
    assert prepared.get("recoveryBridge") is None and completion.get("recoveryBridge") is None
    assert cold["predecessor"]["controller"] == before["current"]
    assert cold["predecessor"]["context"] == before["currentContext"]
    assert cold["predecessorService"] == before["currentService"]
    signed, prepare = prepared["signedOpen"], request["prepare"]
    opened = signed["request"]
    grant = opened["takeover"]["grant"]
    assert opened["predecessor"] == prepare["expectedPredecessor"] == cold_predecessor(before["currentService"])
    assert opened["operation_id"] == prepare["operationID"] == completion["operationID"] == grant["id"]
    assert opened["launch"] == prepare["mountedGreeting"]["launch"]
    assert grant["identity"] == prepare["identity"] == before["identity"]
    assert grant["operation"] == "takeover" and grant["expected_epoch"] == before["currentContext"]["controllerEpoch"]
    assert completion["signedOpenSHA256"] == cold_signed_digest(signed)
    assert completion["baseEpoch"] == prepared["baseEpoch"] == prepare["expectedAllocatedEpoch"] + 1
    assert completion["successorOrigin"] == prepared["successorOrigin"]
    assert completion["successorOrigin"]["rootPublicKey"] == before["rootPublicKey"]
    assert completion["successorOrigin"]["shimLaunchUUID"] == opened["launch"]["shim_launch_uuid"]
    receipt, service = completion["receipt"], completion["successor"]
    assert receipt["grant"] == grant == service["grant"]
    assert service == after["currentService"]
    assert receipt["revision"] == service["open_revision"] > before["currentService"]["open_revision"]
    context = service["context"]
    assert receipt["service_epoch"] == context["service_epoch"] == service["boot"]["service_epoch"]
    assert context["controller_epoch"] == grant["expected_epoch"] + 1
    assert context["controller_key"] == grant["new_key"]
    assert after["currentContext"] == dict(serviceEpoch=context["service_epoch"],
        controllerEpoch=context["controller_epoch"], controllerKey=context["controller_key"])
    for field in ("controller_key", "service_epoch"):
        assert context[field] != before["currentService"]["context"][field]
    assert grant["serial"] > before["currentService"]["grant"]["serial"]
    assert service["boot"]["identity"] == before["identity"]
    assert service["boot"]["bootstrap_key"] == before["currentService"]["boot"]["bootstrap_key"]
    for field in ("tls_root_sha256", "server_spki"):
        assert service["boot"][field] != before["currentService"]["boot"][field]
    assert after["current"]["original"]["signed"] == opened["takeover"]
    assert after["current"]["original"]["recipient"] == request["recipient"]
    assert after["current"]["original"]["requestID"] == request["completionRequestID"]
    assert after["current"]["original"]["serviceEpoch"] == receipt["service_epoch"]
    assert after["current"]["directResult"] == receipt
    for field in ("prepareRequestID", "completionRequestID"):
        replacement.uuid4(request[field])
    assert request["prepareRequestID"] != request["completionRequestID"]
    from managed_prepare_lifecycle_evidence import encoded
    encoded(signed["signature"], 64)
    encoded(opened["takeover"]["signature"], 64)
    return cold


def frozen_committed_cold_proof(before, frozen, diagnostic):
    lifecycle_owner(before)
    assert before["currentContext"]["controllerEpoch"] == 1 and before.get("latestCold") is None
    assert diagnostic.splitlines().count(FIRST_COLD_COMPLETION_REACHED) == 1, "missing exact first-cold cutoff marker"
    cold = committed_cold_edge(before, frozen)
    assert frozen["currentContext"]["controllerEpoch"] == 2
    assert frozen.get("observedWorker") is None, "unexpected admitted worker at the requested cutoff"
    return cold


def recovered_committed_cold_proof(before, frozen, after, diagnostic):
    old = frozen_committed_cold_proof(before, frozen, diagnostic)
    fresh = committed_cold_edge(frozen, after)
    lifecycle_owner(after)
    assert after["currentContext"]["controllerEpoch"] == 3
    assert after["observedWorker"]["workerUUID"] != before["observedWorker"]["workerUUID"]
    assert fresh["completion"]["baseEpoch"] == old["completion"]["baseEpoch"] + 1
    assert fresh["completion"]["successorOrigin"]["binding"] == old["completion"]["successorOrigin"]["binding"]
    assert fresh["completion"]["successorOrigin"]["shimLaunchUUID"] != old["completion"]["successorOrigin"]["shimLaunchUUID"]
    assert fresh["completion"]["operationID"] != old["completion"]["operationID"]


def committed_cold_births(daemon_pid, cold, births, storage):
    api, child = cold_attempt_births(daemon_pid, cold, births)
    expected = {(p.pid, p.identity, p.pidversion) for p in (api, child, storage)}
    assert len(expected) == 3 and len(births) == 3
    assert {(p.pid, p.identity, p.pidversion) for p in births} == expected, "unknown attempted native birth"


def cold_attempt_births(daemon_pid, pending, births):
    """Join public attempted recipient to already observed kernel births, never PID alone."""
    recipient = pending["request"]["recipient"]
    api = [p for p in births if p.pid == daemon_pid and p.identity[2] == recipient["daemonUniqueID"]]
    child = [p for p in births if p.pid == recipient["childPID"] and p.identity[2] == recipient["childUniqueID"]]
    assert len(api) == len(child) == 1, "missed exact attempted daemon/controller birth"
    assert api[0].identity != child[0].identity
    for process in (api[0], child[0]):
        replacement.native_proof(process)
    return api[0], child[0]


def observe_cold_controller(daemon, record):
    """The scoped launcher census excludes the separate controller executable.

    Use the frozen recipient only to locate a candidate, then independently pin
    its executable, argv, parent and kernel birth while it is still alive.
    """
    pending = record.get("pendingCold")
    if pending is None:
        return None
    recipient = pending["request"]["recipient"]
    child = _kernel_process(recipient["childPID"])
    if child is None:
        return None  # Absence is not a captured birth; the final join still requires one.
    replacement.native_proof(child)
    executable = daemon.binary.with_name("cengine-storage-controller")
    assert child.pid == recipient["childPID"] and child.identity[2] == recipient["childUniqueID"]
    assert Path(child.executable).resolve(strict=True) == executable.resolve(strict=True)
    assert child.arguments == (str(executable), "--lifecycle-v2")
    assert child.parent_pid == daemon.process.pid
    parent = _kernel_process(daemon.process.pid)
    replacement.native_proof(parent)
    assert parent.identity[2] == recipient["daemonUniqueID"]
    current = _kernel_process(child.pid)
    if current is None:
        return None  # Natural exit is not a stable observation; retain no new birth.
    assert current == child, "controller birth changed during observation"
    return child


def observe_cold_births(daemon, initial, *, timeout=60):
    """Synchronous on_spawn observer: no readiness, signals or journal writes."""
    seen = {}
    deadline = time.monotonic() + timeout
    while True:
        for process in compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)):
            replacement.native_proof(process)
            assert all(process.identity != old.identity for old in initial), "old native birth survived strict shutdown"
            seen[(process.pid, process.identity, process.pidversion)] = process
        record, _ = replacement.read_public(daemon.root / "managed-storage-owner/state.json")
        child = observe_cold_controller(daemon, record)
        if child is not None:
            assert all(child.identity != old.identity for old in initial)
            seen[(child.pid, child.identity, child.pidversion)] = child
        if daemon.process.poll() is not None:
            break
        assert time.monotonic() < deadline, "cold startup did not exit naturally"
        time.sleep(0.01)
    assert any(p.pid == daemon.process.pid for p in seen.values()), "missed actual failed daemon birth"
    assert any(len(p.arguments) > 1 and p.arguments[1] == "vm-shim" for p in seen.values()), "missed attempted storage birth"
    return list(seen.values())


@pytest.mark.compat("RTM-129")
def test_lifecycle_v2_interrupted_cold_l2_recovers(client, daemon, shared):
    interrupted_cold_l2_recovery(client, daemon, shared)


@pytest.mark.compat("RTM-130")
def test_lifecycle_v2_guest_initramfs_update_cold_recovery(client, daemon, shared):
    interrupted_cold_l2_recovery(client, daemon, shared, guest_update=True)


def interrupted_cold_l2_recovery(client, daemon, shared, *, guest_update=False):
    from managed_prepare_lifecycle_evidence import storage_target
    from test_managed_storage_recovery import parent_deadline

    with parent_deadline(time.monotonic() + 420):
        peers = [create_peer(client, shared, side) for side in ("left", "right")]
        for peer in peers:
            peer.update(restart_policy={"Name": "always"})
            peer.start()
            mount_proof(daemon, peer)
        ids = {peer.id for peer in peers}
        seed = "cold-l2-seed-" + uuid.uuid4().hex
        exchange(*peers, seed)
        for peer, side in zip(peers, ("left", "right")):
            _exec(peer, "sh", "-ec", f"cp /data/{side} /data/seed-{side}; sync")
        disk = disk_identity(daemon.root)
        root_stat = daemon.root.stat()
        root_identity = (root_stat.st_dev, root_stat.st_ino)
        binary = daemon.binary
        initial, _, _ = replacement.lifecycle_owner(daemon.root)
        before, manifest = initial["checkpoint"], initial["manifest"]
        native = native_snapshot(daemon, ids)
        if guest_update:
            history = storage_launch_history(daemon.root)
            old_digest = hashlib.sha256(daemon.storage_initramfs.read_bytes()).hexdigest()
            old_spec = storage_guest_proof(daemon, native, old_digest)
        census = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
        daemon.process.terminate()
        assert daemon.process.wait(timeout=15) == 0
        daemon.stop()
        assert native_snapshot(daemon, ids) == native
        _strict_shutdown(daemon)
        for target in census:
            wait_for_value(lambda: replacement.exact_exit(target, _kernel_process(target.pid)), bool,
                           timeout=30, description="initial native birth ended by supported shutdown")
        assert not compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
        if guest_update:
            # Every old writer has positively exited before staging/selecting assets.
            assert storage_launch_history(daemon.root) == history
            selector = daemon.root / "infrastructure/shim.json"
            selector_bytes = selector.read_bytes()
            owner_directory = daemon.root / "managed-storage-owner"
            owner_bytes = {path: path.read_bytes() for path in owner_directory.glob("*.json")}
            source = daemon.storage_initramfs.parent
            assert daemon.kernel == source / "vmlinux"
            assert daemon.container_initramfs == source / "container-initramfs.cpio.gz"
            destination = daemon.work / "guest-update"
            expected_digest = stage_guest_update(source, destination)
            assert expected_digest != old_spec["expectedInitramfsSHA256"]
            daemon.kernel = destination / "vmlinux"
            daemon.container_initramfs = destination / "container-initramfs.cpio.gz"
            daemon.storage_initramfs = destination / "storage-initramfs.cpio.gz"
            assert storage_launch_history(daemon.root) == history
            assert selector.read_bytes() == selector_bytes
            assert {path: path.read_bytes() for path in owner_directory.glob("*.json")} == owner_bytes
        path = daemon.root / "managed-storage-owner/state.json"
        attempted_births = []
        frozen = None

        def preserved():
            assert daemon.binary == binary == daemon.owner_binary
            info = daemon.root.stat()
            assert (info.st_dev, info.st_ino) == root_identity
            assert disk_identity(daemon.root) == disk
            assert replacement.read_public(daemon.root / "managed-storage-owner/manifest.json")[0] == manifest

        def observe():
            attempted_births.extend(observe_cold_births(daemon, census))

        def qualify(failed):
            nonlocal frozen
            assert failed is daemon and daemon.process.poll() > 0
            preserved()
            frozen, _ = replacement.read_public(path)
            frozen_cold_proof(before, frozen)
            return True  # Natural failure only; phase qualification awaits the ROOT bridge.

        daemon.start(on_spawn=observe, qualify_lifecycle_fault=qualify)
        assert frozen is not None
        pending = frozen["pendingCold"]
        owner = {**manifest, **pending["prepared"]["successorOrigin"]}
        target = storage_target(daemon, owner, attempted_births, replacement.read_public)
        cold_attempt_births(daemon.process.pid, pending, attempted_births)
        if guest_update:
            attempted_history = storage_launch_history(daemon.root)
            assert all(attempted_history.get(path) == data for path, data in history.items()), "old launch history changed"
            attempted_generation = Path(owner["shimLaunchUUID"])
            assert set(attempted_history) - set(history) == {
                attempted_generation / name for name in ("spec.json", "intent.json", "launch.json")}
            attempted_spec = json.loads(attempted_history[attempted_generation / "spec.json"])
            assert attempted_spec["expectedInitramfsSHA256"] == expected_digest
            assert Path(attempted_spec["initialRamdiskPath"]).resolve() == daemon.storage_initramfs.resolve()
        # Allow natural cleanup first. A remaining storage orphan can be retired
        # only via its positively observed immutable launch and native audit birth.
        deadline = time.monotonic() + 15
        while not replacement.exact_exit(target, _kernel_process(target.pid)) and time.monotonic() < deadline:
            time.sleep(0.05)
        if not replacement.exact_exit(target, _kernel_process(target.pid)):
            live = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
            current = storage_target(daemon, owner, live, replacement.read_public)
            assert (current.pid, current.identity, current.pidversion) == (target.pid, target.identity, target.pidversion)

            def before_signal():
                preserved()
                assert daemon.process.poll() > 0
                assert replacement.read_public(path)[0] == frozen
                assert compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)) == live
                assert _kernel_process(current.pid) == current
                assert storage_target(daemon, owner, live, replacement.read_public) == current

            delivery = replacement.signal_storage(current, before_signal=before_signal)
            assert delivery["native_result"] == 0 and delivery["signal"] == "SIGKILL"
        for target in attempted_births:
            wait_for_value(lambda: replacement.exact_exit(target, _kernel_process(target.pid)), bool,
                           timeout=30, description="failed attempted native birth positively gone")
        assert not compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)), "unowned orphan; fail retained"
        assert replacement.read_public(path)[0] == frozen
        preserved()
        daemon.start()  # Same sealed binary; protected resolve-dead then genuinely bridged C+2.
        assert client.ping()

        def running():
            for peer in peers:
                peer.reload()
            return all(peer.status == "running" and peer.attrs["State"]["Running"] for peer in peers)

        wait_for_value(running, bool, timeout=120, description="automatic always-policy C+2 recovery")
        after, _ = replacement.read_public(path)
        recovered_cold_proof(before, frozen, after)
        preserved()
        fresh = native_snapshot(daemon, ids)
        for key in native:
            assert fresh[key]["native"][1] != native[key]["native"][1]
            assert fresh[key]["status"]["shimLaunchUUID"] != native[key]["status"]["shimLaunchUUID"]
            assert all(fresh[key]["native"][1] != p.identity for p in attempted_births)
        recovered_origin = after["latestCold"]["completion"]["successorOrigin"]
        assert fresh["storage"]["status"]["shimLaunchUUID"] == recovered_origin["shimLaunchUUID"]
        recovered_target = storage_target(daemon, {**manifest, **recovered_origin},
            compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)), replacement.read_public)
        assert (recovered_target.pid, recovered_target.identity, recovered_target.pidversion) == fresh["storage"]["native"]
        if guest_update:
            new_spec = storage_guest_proof(daemon, fresh, expected_digest)
            assert new_spec["expectedInitramfsSHA256"] != old_spec["expectedInitramfsSHA256"]
            retained = storage_launch_history(daemon.root)
            assert all(retained.get(path) == data for path, data in attempted_history.items()), "old launch history changed"
            new_generation = Path(new_spec["shimLaunchUUID"])
            assert new_generation != attempted_generation
            assert set(retained) - set(history) == {
                generation / name for generation in (attempted_generation, new_generation)
                for name in ("spec.json", "intent.json", "launch.json")}
            assert retained[new_generation / "spec.json"] == (daemon.root / "infrastructure/shim.json").read_bytes()
        assert {peer.id for peer in client.containers.list(all=True) if peer.id in ids} == ids
        for peer in peers:
            assert peer.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"
            mount_proof(daemon, peer)
            for side in ("left", "right"):
                assert _exec(peer, "cat", "/data/seed-" + side) == (seed + "-" + side).encode()
        exchange(*peers, "cold-l2-recovered-" + uuid.uuid4().hex)


@pytest.mark.compat("RTM-132")
def test_lifecycle_v2_committed_unenrolled_cold_recovery(client, daemon, shared):
    from managed_prepare_lifecycle_evidence import storage_target
    from test_managed_storage_recovery import parent_deadline
    with parent_deadline(time.monotonic() + 420):
        peers = [create_peer(client, shared, side) for side in ('left', 'right')]
        for peer in peers:
            peer.update(restart_policy={'Name': 'always'})
            peer.start()
            peer.reload()
            assert peer.status == 'running' and peer.attrs['HostConfig']['RestartPolicy']['Name'] == 'always'
            mount_proof(daemon, peer)
        ids = {peer.id for peer in peers}
        mounts = {peer.id: peer.attrs['HostConfig']['Mounts'] for peer in peers}
        volume_id = shared.id
        seed = 'committed-cold-seed-' + uuid.uuid4().hex
        exchange(*peers, seed)
        for peer, side in zip(peers, ('left', 'right')):
            _exec(peer, 'sh', '-ec', f'cp /data/{side} /data/seed-{side}; sync')
        disk = disk_identity(daemon.root)
        root_stat = daemon.root.stat()
        root_identity = (root_stat.st_dev, root_stat.st_ino)
        binary = daemon.binary
        initial, _, _ = replacement.lifecycle_owner(daemon.root)
        before, manifest = (initial['checkpoint'], initial['manifest'])
        assert before['currentContext']['controllerEpoch'] == 1
        native = native_snapshot(daemon, ids)
        census = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
        daemon.process.terminate()
        assert daemon.process.wait(timeout=15) == 0
        daemon.stop()
        assert native_snapshot(daemon, ids) == native
        _strict_shutdown(daemon)
        for target in census:
            wait_for_value(lambda: replacement.exact_exit(target, _kernel_process(target.pid)), bool,
                           timeout=30, description='initial native birth ended by supported shutdown')
        assert not compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
        path = daemon.root / 'managed-storage-owner/state.json'
        attempted_births = []
        frozen = None
        diagnostic = None
        log_offset = daemon.log_path.stat().st_size

        def preserved():
            assert daemon.binary == binary == daemon.owner_binary
            info = daemon.root.stat()
            assert (info.st_dev, info.st_ino) == root_identity
            assert disk_identity(daemon.root) == disk
            assert replacement.read_public(daemon.root / 'managed-storage-owner/manifest.json')[0] == manifest

        def observe():
            attempted_births.extend(observe_cold_births(daemon, census))

        def qualify(failed):
            nonlocal frozen, diagnostic
            assert failed is daemon and daemon.process.poll() > 0
            preserved()
            frozen, _ = replacement.read_public(path)
            with daemon.log_path.open('rb') as log:
                log.seek(log_offset)
                raw = log.read(65537)
            assert len(raw) <= 65536, 'unbounded cold fault diagnostic'
            diagnostic = raw.decode('utf-8', errors='strict')
            frozen_committed_cold_proof(before, frozen, diagnostic)
            return True
        daemon.start(on_spawn=observe, qualify_lifecycle_fault=qualify)
        assert frozen is not None
        cold = frozen['latestCold']
        owner = {**manifest, **cold['completion']['successorOrigin']}
        target = storage_target(daemon, owner, attempted_births, replacement.read_public)
        committed_cold_births(daemon.process.pid, cold, attempted_births, target)
        # Natural cleanup first; only an exact, positively observed storage orphan may be retired.
        deadline = time.monotonic() + 15
        while not replacement.exact_exit(target, _kernel_process(target.pid)) and time.monotonic() < deadline:
            time.sleep(0.05)
        if not replacement.exact_exit(target, _kernel_process(target.pid)):
            live = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
            current = storage_target(daemon, owner, live, replacement.read_public)
            assert live == [current], 'unknown live native birth; do not signal'
            assert (current.pid, current.identity, current.pidversion) == (target.pid, target.identity, target.pidversion)

            def before_signal():
                preserved()
                assert daemon.process.poll() > 0
                assert replacement.read_public(path)[0] == frozen
                assert compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)) == live
                assert _kernel_process(current.pid) == current
                assert storage_target(daemon, owner, live, replacement.read_public) == current
            delivery = replacement.signal_storage(current, before_signal=before_signal)
            assert delivery['native_result'] == 0 and delivery['signal'] == 'SIGKILL'
        for target in attempted_births:
            wait_for_value(lambda: replacement.exact_exit(target, _kernel_process(target.pid)), bool,
                           timeout=30, description='failed attempted native birth positively gone')
        assert not compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)), 'unowned orphan; fail retained'
        assert replacement.read_public(path)[0] == frozen
        preserved()
        # Same engine/helper pair and profile: the authenticated C2-only cut is inert at C3.
        daemon.start()
        assert client.ping()

        def running():
            for peer in peers:
                peer.reload()
            return all((peer.status == 'running' and peer.attrs['State']['Running'] for peer in peers))
        wait_for_value(running, bool, timeout=120, description='automatic always-policy committed C3 recovery')
        after, _ = replacement.read_public(path)
        recovered_committed_cold_proof(before, frozen, after, diagnostic)
        preserved()
        fresh = native_snapshot(daemon, ids)
        for key in native:
            assert fresh[key]['native'][1] != native[key]['native'][1]
            assert fresh[key]['status']['shimLaunchUUID'] != native[key]['status']['shimLaunchUUID']
            assert all((fresh[key]['native'][1] != p.identity for p in attempted_births))
        recovered_origin = after['latestCold']['completion']['successorOrigin']
        assert fresh['storage']['status']['shimLaunchUUID'] == recovered_origin['shimLaunchUUID']
        recovered_target = storage_target(daemon, {**manifest, **recovered_origin},
            compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)), replacement.read_public)
        assert (recovered_target.pid, recovered_target.identity, recovered_target.pidversion) == fresh['storage']['native']
        assert {peer.id for peer in client.containers.list(all=True) if peer.id in ids} == ids
        assert client.volumes.get(shared.name).id == volume_id
        for peer in peers:
            assert peer.attrs['HostConfig']['Mounts'] == mounts[peer.id]
            assert peer.attrs['HostConfig']['RestartPolicy']['Name'] == 'always'
            mount_proof(daemon, peer)
            for side in ('left', 'right'):
                assert _exec(peer, 'cat', '/data/seed-' + side) == (seed + '-' + side).encode()
        exchange(*peers, 'committed-cold-recovered-' + uuid.uuid4().hex)


@pytest.mark.compat("RTM-124")
def test_lifecycle_v2_live_restart_after_two_cold_recoveries(client, daemon, shared):
    from managed_prepare_lifecycle_evidence import storage_target
    from test_managed_storage_recovery import parent_deadline

    with parent_deadline(time.monotonic() + 300):
        peers = [create_peer(client, shared, name) for name in ("seed-left", "seed-right")]
        for peer in peers:
            peer.start()
            mount_proof(daemon, peer)
        seed = "cold-seed-" + uuid.uuid4().hex
        exchange(peers[0], peers[1], seed)
        for peer, side in zip(peers, ("left", "right")):
            _exec(peer, "sh", "-ec", f"cp /data/{side} /data/seed-{side}; sync")
        ids = {peer.id for peer in peers}
        native = native_snapshot(daemon, ids)
        census = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
        workloads = [next(p for p in census if p.pid == native[id]["native"][0]) for id in ids]
        disk = disk_identity(daemon.root)
        path = daemon.root / "managed-storage-owner/state.json"
        initial, _ = replacement.read_public(path)
        lifecycle_owner(initial)
        assert initial["latestCold"] is None

        def receipts():
            manifest, state, _ = replacement.public_state(daemon.root)
            return replacement.exact_receipts(manifest, state, shared.name,
                                              [peer.id for peer in peers], stopped=True)

        for peer in peers:
            peer.stop(timeout=1)
            peer.reload()
            assert peer.attrs["State"]["Running"] is False
        retired = wait_for_value(receipts, bool, timeout=30,
                                 description="both seed peers have exact PREPARE/runtime drain receipts")
        # Normal API removal terminates stopped shims but retains managed intent
        # history. Never signal workloads or infer native exit from Docker state.
        for peer in peers:
            peer.remove()
        for process in workloads:
            wait_for_value(lambda: replacement.exact_exit(process, _kernel_process(process.pid)),
                           bool, timeout=30, description="retired seed workload native exit")
        replacement.historical_receipts(retired, receipts())
        assert native_snapshot(daemon, set()) == {"storage": native["storage"]}
        # The owner checkpoints its census on lifecycle transitions, not every
        # workload journal update. The first cold transition captures these refs.
        retired_references = None

        # E1 has real retired PREPAREs. E2 must have NONE: a single cold restart
        # would leave latestCold.predecessor referenced and miss this regression.
        for _ in range(2):
            daemon.stop(kill=True)
            assert daemon.process.poll() == -9
            assert native_snapshot(daemon, set()) == {"storage": native["storage"]}
            owner_record, owner, _ = replacement.lifecycle_owner(daemon.root)
            before = owner_record["checkpoint"]
            if retired_references is not None:
                assert before["references"] == retired_references
            frozen = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
            target = storage_target(daemon, owner, frozen, replacement.read_public)
            assert (target.pid, target.identity, target.pidversion) == native["storage"]["native"]

            def before_signal():
                assert daemon.process.poll() == -9
                assert compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)) == frozen
                assert _kernel_process(target.pid) == target
                assert disk_identity(daemon.root) == disk
                replacement.historical_receipts(retired, receipts())
                current, current_owner, _ = replacement.lifecycle_owner(daemon.root)
                assert current == owner_record
                assert storage_target(daemon, current_owner, frozen, replacement.read_public) == target

            delivery = replacement.signal_storage(target, before_signal=before_signal)
            assert delivery["native_result"] == 0 and delivery["signal"] == "SIGKILL"
            wait_for_value(lambda: replacement.exact_exit(target, _kernel_process(target.pid)),
                           bool, timeout=30, description="positively signalled storage native exit")
            replacement.unchanged_processes(
                frozen, compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,)), target)
            daemon.start()
            assert client.ping()
            native = native_snapshot(daemon, set())
            assert native["storage"]["native"][1] != target.identity, "fresh storage kernel birth required"
            assert disk_identity(daemon.root) == disk
            after, _ = replacement.read_public(path)
            lifecycle_owner(after)
            assert after["identity"] == initial["identity"]
            assert after["rootPublicKey"] == initial["rootPublicKey"]
            if retired_references is None:
                assert {ref["id"] for ref in after["references"]} == {i["id"] for i in retired["intents"]}
                assert all(ref["original"] == initial["currentContext"] for ref in after["references"])
                retired_references = after["references"]
            else:
                assert after["references"] == retired_references
            assert after["latestCold"]["predecessor"]["context"] == before["currentContext"]
            assert after["currentContext"]["serviceEpoch"] != before["currentContext"]["serviceEpoch"]
            assert after["currentContext"]["controllerEpoch"] == before["currentContext"]["controllerEpoch"] + 1
            replacement.historical_receipts(retired, receipts())

        audit_only = after["latestCold"]["predecessor"]["context"]
        assert audit_only != initial["currentContext"] and audit_only != after["currentContext"]
        assert audit_only in [row["context"] for row in after["contexts"]]

        def assert_audit_only(record):
            assert record["latestCold"] == after["latestCold"]
            assert audit_only in [row["context"] for row in record["contexts"]]
            for ref in record["references"]:
                assert ref["original"] != audit_only
                recovery = ref.get("recovery")
                assert recovery is None or {key: recovery[key] for key in audit_only} != audit_only

        assert_audit_only(after)
        fresh = [create_peer(client, shared, name) for name in ("live-left", "live-right")]
        for peer in fresh:
            peer.start()
            mount_proof(daemon, peer)
            for side in ("left", "right"):
                assert _exec(peer, "cat", "/data/seed-" + side) == (seed + "-" + side).encode()
        exchange(fresh[0], fresh[1], "cold-live-" + uuid.uuid4().hex)
        live_ids = {peer.id for peer in fresh}
        original = native_snapshot(daemon, live_ids)
        assert original["storage"] == native["storage"]
        for _ in range(2):
            current, _ = replacement.read_public(path)
            lifecycle_owner(current)
            assert_audit_only(current)
            daemon.stop(kill=True)
            assert daemon.process.poll() == -9
            assert native_snapshot(daemon, live_ids) == original
            daemon.start()
            assert client.ping()
            assert native_snapshot(daemon, live_ids) == original
            assert disk_identity(daemon.root) == disk
            for peer in fresh:
                peer.reload()
                assert peer.status == "running" and peer.attrs["RestartCount"] == 0
                mount_proof(daemon, peer)
            exchange(fresh[0], fresh[1], "cold-reattached-" + uuid.uuid4().hex)
            current, _ = replacement.read_public(path)
            lifecycle_owner(current)
            assert_audit_only(current)
            replacement.historical_receipts(retired, receipts())


def replacement_receipts(queue, validate, request, raw, marker, *, timeout=60):
    seen = {}
    stem = request["operationUUID"]
    deadline = time.monotonic() + timeout
    while True:
        validate()
        try:
            replacement.queue_file(queue, stem + ".failed.json")
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("production worker replacement failed; retain artifacts")
        try:
            for suffix in (".request.json", ".pending.json", ".succeeded.json"):
                name = stem + suffix
                value = replacement.queue_file(queue, name, 512 if suffix == ".request.json" else 1048576)
                assert name not in seen or seen[name] == value, "immutable replacement artifact changed"
                seen[name] = value
            claimed, stamp = seen[stem + ".request.json"]
            assert claimed == raw and stamp[:2] == marker, "exact owned request claim required"
            replacement.settled_worker_artifacts(queue, stem, seen)
            return (json.loads(seen[stem + ".pending.json"][0]),
                    json.loads(seen[stem + ".succeeded.json"][0]), seen)
        except FileNotFoundError:
            assert time.monotonic() < deadline, "production replacement deadline"
            time.sleep(0.05)


def lifecycle_replacement_proof(before, after, pending, succeeded, request, ids, submitted, observed):
    old, new = lifecycle_owner(before), lifecycle_owner(after)
    assert request["store"] == before["identity"]["store"] and request["predecessor"] == old
    for field in ("identity", "rootPublicKey", "provenanceReference", "current"):
        assert before[field] == after[field], "ROOT/store/generation/controller changed"
    old_service, new_service = before["currentService"], after["currentService"]
    assert old_service["grant"] == new_service["grant"]
    for field in ("controller_epoch", "controller_key"):
        assert old_service["context"][field] == new_service["context"][field]
    assert old_service["boot"]["bootstrap_key"] == new_service["boot"]["bootstrap_key"]
    for field in old:
        assert new[field] != old[field], "fresh E and worker required"
    for field in ("tls_root_sha256", "server_spki"):
        assert new_service["boot"][field] != old_service["boot"][field], "fresh TLS required"
    assert after["revision"] > before["revision"]
    assert new_service["open_revision"] > old_service["open_revision"]
    proof = {"controllerEpoch": old_service["context"]["controller_epoch"],
             "controllerKey": old_service["context"]["controller_key"], "rootPublicKey": before["rootPublicKey"]}
    common = {"schema", "counter", "phase", "request", "proof"}
    assert set(pending) == common
    assert set(succeeded) == common | {"ownerRequest", "successor", "containedContainerIDs"}
    assert pending["phase"] == "pending" and succeeded["phase"] == "succeeded"
    for receipt in (pending, succeeded):
        assert type(receipt["schema"]) is int and receipt["schema"] == 1
        assert type(receipt["counter"]) is int and receipt["counter"] == 1
        assert receipt["request"] == request and receipt["proof"] == proof
    assert len(ids) == len(set(ids)) == 2 and succeeded["containedContainerIDs"] == sorted(ids)
    assert succeeded["successor"] == new
    actual = succeeded["ownerRequest"]
    assert set(actual) == {"operationUUID", "predecessor", "nowUnixSeconds"}
    assert actual["operationUUID"] == request["operationUUID"] and actual["predecessor"] == old
    assert type(actual["nowUnixSeconds"]) is int and submitted <= actual["nowUnixSeconds"] <= observed
    confirmation = after["latestServiceConfirmation"]
    assert confirmation == {"request": {"operation_id": request["operationUUID"], "predecessor": old_service},
                            "successor": new_service}
    retry = after["latestServiceRequest"]
    assert retry["request"] == confirmation["request"] and retry["predecessorWorkerUUID"] == old["workerUUID"]
    assert retry["nowUnixSeconds"] == actual["nowUnixSeconds"]
    link = after["latestServiceChange"]
    assert link["operationID"] == request["operationUUID"]
    assert link["predecessor"] == before["currentContext"] and link["successor"] == after["currentContext"]
    assert link["revision"] == new_service["open_revision"]


@pytest.mark.compat("RTM-120")
def test_lifecycle_v2_same_daemon_worker_replacement(client, daemon, shared):
    # Reuse the owned queue's bounded, no-overwrite publication, not a private
    # owner invocation or worker kill. Public receipts are evidence only.
    from test_managed_storage_recovery import parent_deadline
    with parent_deadline(time.monotonic() + 180):
        disk_baseline = replacement.disk_budget(daemon.root)["allocated"]
        peers = [create_peer(client, shared, name) for name in ("left", "right")]
        for peer in peers:
            peer.start()
            mount_proof(daemon, peer)
        seed = "replacement-seed-" + uuid.uuid4().hex
        exchange(peers[0], peers[1], seed)
        for peer, side in zip(peers, ("left", "right")):
            _exec(peer, "sh", "-ec", f"cp /data/{side} /data/seed-{side}; sync")
        for peer in peers:
            for side in ("left", "right"):
                assert _exec(peer, "cat", "/data/seed-" + side) == (seed + "-" + side).encode()
        ids = {peer.id for peer in peers}
        native = native_snapshot(daemon, ids)
        census = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
        workloads = [next(p for p in census if p.pid == native[id]["native"][0]) for id in ids]
        api = _kernel_process(daemon.process.pid)
        assert api is not None and api.identity is not None and api.pidversion is not None
        root = daemon.root.stat()
        root_identity = {"device": root.st_dev, "inode": root.st_ino}
        disk = disk_identity(daemon.root)
        path = daemon.root / "managed-storage-owner/state.json"
        before, _ = replacement.read_public(path)
        scope = lifecycle_owner(before)
        assert not before["serviceLinks"] and before.get("latestServiceChange") is None
        request, raw = replacement.worker_request(str(uuid.uuid4()), before["identity"]["store"], scope)
        with replacement.replacement_queue(daemon.root, root_identity) as (queue, validate):
            assert native_snapshot(daemon, ids) == native
            for peer in peers:
                peer.reload()
                assert peer.attrs["State"]["Running"] is True
            replacement.disk_budget(daemon.root, disk_baseline)
            validate()
            submitted = int(time.time())
            marker = replacement.publish_worker_request(queue, raw)
            pending, succeeded, seen = replacement_receipts(queue, validate, request, raw, marker)
            observed = int(time.time())
            for process in workloads:
                wait_for_value(lambda: replacement.exact_exit(process, _kernel_process(process.pid)),
                               bool, timeout=30, description="actual old workload native exit")
            assert {p.pid: p for p in compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))} == {
                p.pid: p for p in census if p not in workloads}
            for peer in peers:
                assert peer.wait(timeout=30)["StatusCode"] == 137
                peer.reload()
                assert peer.attrs["State"]["Running"] is False and peer.attrs["State"]["ExitCode"] == 137
            # Do not ask native_snapshot to find now-exited old containers.
            assert native_snapshot(daemon, set()) == {"storage": native["storage"]}
            after, _ = replacement.read_public(path)
            lifecycle_replacement_proof(before, after, pending, succeeded, request, ids, submitted, observed)
            replacement.disk_budget(daemon.root, disk_baseline)
            fresh = [create_peer(client, shared, name) for name in ("fresh-left", "fresh-right")]
            for peer in fresh:
                peer.start()
                mount_proof(daemon, peer)
                for side in ("left", "right"):
                    assert _exec(peer, "cat", "/data/seed-" + side) == (seed + "-" + side).encode()
            exchange(fresh[0], fresh[1], "replacement-new-" + uuid.uuid4().hex)
            assert native_snapshot(daemon, {peer.id for peer in fresh})["storage"] == native["storage"]
            assert daemon.process.poll() is None and _kernel_process(api.pid) == api
            assert (daemon.root.stat().st_dev, daemon.root.stat().st_ino) == (root.st_dev, root.st_ino)
            assert disk_identity(daemon.root) == disk
            final, _ = replacement.read_public(path)
            assert lifecycle_owner(final) == lifecycle_owner(after)
            for field in ("identity", "rootPublicKey", "currentService", "latestServiceConfirmation", "latestServiceRequest"):
                assert final[field] == after[field]
            replacement.settled_worker_artifacts(queue, request["operationUUID"], seen)
            validate()
            replacement.disk_budget(daemon.root, disk_baseline)


def fault_diagnostics(daemon):
    # The compiled fault/positive VZ callback run in the owned storage shim.
    path = daemon.root / "infrastructure/shim.log"
    with path.open("rb") as stream:
        data = stream.read(1048577)
    assert len(data) <= 1048576, "fault diagnostic log exceeded bound"
    lines = data.splitlines()
    return lines.count(FAULT_REACHED.encode()), lines.count(FAULT_STOPPED.encode())


def qualify_initialization_fault(daemon, *, timeout=15):
    # Called only after bounded, positive (not signalled) daemon exit, before
    # harness stop/kill-all. The shim may still be completing its 10s shutdown
    # grace period. Passively await the positive callback, never force shutdown.
    # EOF/timeout/forced termination and diagnostic errors never qualify.
    deadline = time.monotonic() + timeout
    while True:
        reached, stopped = fault_diagnostics(daemon)
        if reached > 1 or stopped > 1:
            return False
        if (reached, stopped) == (1, 1):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.1, remaining))


def resume_initialization(daemon):
    assert daemon.process is None and daemon.root_retained
    daemon.start(qualify_lifecycle_fault=qualify_initialization_fault)
    before = disk_identity(daemon.root)
    marker = daemon.root / "managed-storage-initialization/manifest.json"
    marker_bytes = marker.read_bytes()
    marker_stat = marker.stat()
    manifest = json.loads(marker_bytes)
    assert manifest["version"] == "storage-host-initialization.v2"
    assert manifest["binding"]["version"] == "storage-host-binding.v2"
    for field in ("root", "backing"):
        assert set(manifest["binding"][field]) == {"inode", "volume_uuid"}
    assert uuid.UUID(manifest["binding"]["ext4_uuid"]).bytes == before[3]
    assert manifest["binding"]["backing"]["inode"] == before[1]
    # Same compiled fault binary: only fresh configure fails; resume is untouched.
    binary = daemon.binary
    daemon.start()
    assert daemon.binary == binary
    assert disk_identity(daemon.root) == before
    assert marker.read_bytes() == marker_bytes
    assert (marker.stat().st_dev, marker.stat().st_ino) == (marker_stat.st_dev, marker_stat.st_ino)
    assert (marker.parent / "completed.json").is_file()
    assert json.loads((marker.parent / "admitted.json").read_bytes()) is True
    assert fault_diagnostics(daemon) == (1, 1), "resume unexpectedly reinjected the fresh-only fault"


@pytest.mark.compat("RTM-119")
@pytest.mark.parametrize("daemon", ["lifecycle-first-start"], indirect=True)
def test_lifecycle_v2_first_initialization_failure_resumes(client, daemon, shared):
    # The daemon override has proven first-start fault and same-store resume
    # before client/shared (and the autouse Docker CLI target check) can run.
    peers = [create_peer(client, shared, name) for name in ("left", "right")]
    for peer in peers:
        peer.start()
        mount_proof(daemon, peer)
    assert fault_diagnostics(daemon) == (1, 1), "fresh-only fault was reinjected"
    exchange(peers[0], peers[1], "resumed-" + uuid.uuid4().hex)


def replacement_observation_shape(value):
    """Closed public diagnostic schema, never a ROOT confirmation/capability."""
    def keys(item, expected):
        assert type(item) is dict and set(item) == set(expected), "invalid native observation schema"
    def integer(item, minimum=1):
        assert type(item) is int and minimum <= item <= 2**64 - 1, "invalid native observation integer"
    def digest(item):
        assert type(item) is str and re.fullmatch(r"[0-9a-f]{64}", item), "invalid native observation digest"
    def identity(item):
        keys(item, ("store", "generation", "binding"))
        replacement.uuid4(item["store"])
        integer(item["generation"])
        digest(item["binding"])
    keys(value, ("observation", "predecessorWorkerUUID", "workerUUID"))
    for field in ("predecessorWorkerUUID", "workerUUID"):
        replacement.uuid4(value[field])
    assert value["predecessorWorkerUUID"] != value["workerUUID"]
    observation = value["observation"]
    keys(observation, ("request", "successor"))
    keys(observation["request"], ("operation_id", "predecessor"))
    replacement.uuid4(observation["request"]["operation_id"])
    for service in (observation["request"]["predecessor"], observation["successor"]):
        keys(service, ("grant", "boot", "context", "open_revision"))
        integer(service["open_revision"])
        grant, boot, context = service["grant"], service["boot"], service["context"]
        keys(grant, ("operation", "id", "identity", "serial", "expected_epoch", "new_key"))
        assert grant["operation"] in ("initialize", "takeover")
        replacement.uuid4(grant["id"])
        identity(grant["identity"])
        integer(grant["serial"])
        integer(grant["expected_epoch"], 0)
        digest(grant["new_key"])
        keys(boot, ("identity", "service_epoch", "tls_root_sha256", "server_spki", "bootstrap_key"))
        identity(boot["identity"])
        replacement.uuid4(boot["service_epoch"])
        for field in ("tls_root_sha256", "server_spki", "bootstrap_key"):
            digest(boot[field])
        keys(context, ("service_epoch", "controller_epoch", "controller_key"))
        replacement.uuid4(context["service_epoch"])
        integer(context["controller_epoch"])
        digest(context["controller_key"])
        assert boot["identity"] == grant["identity"]
        assert boot["service_epoch"] == context["service_epoch"]
        assert context["controller_epoch"] == grant["expected_epoch"] + 1
        assert context["controller_key"] == grant["new_key"]


def replacement_pause_observation(daemon):
    # The owned daemon's stderr sink, NOT infrastructure/shim.log. Only the
    # sealed fault caller emits this native observation; no engine reads it.
    with daemon.log_path.open("rb") as stream:
        data = stream.read(1048577)
    assert len(data) <= 1048576, "daemon diagnostic log exceeded bound"
    marker = REPLACEMENT_PAUSED.encode()
    lines = [line for line in data.splitlines(keepends=True) if marker in line]
    assert len(lines) <= 1, "duplicate replacement cut"
    if not lines:
        return None
    line = lines[0]
    assert line.startswith(marker + b" "), "malformed replacement marker prefix"
    if not line.endswith(b"\n"):
        return None  # In-progress append cannot qualify; bounded caller keeps waiting.
    payload = line[len(marker) + 1:-1]
    assert 0 < len(payload) <= 65536, "native observation payload bound"
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, "duplicate native observation JSON key"
            result[key] = value
        return result
    def invalid_constant(value):
        raise AssertionError("non-finite native observation JSON number")
    observation = json.loads(payload, object_pairs_hook=unique, parse_constant=invalid_constant)
    assert json.dumps(observation, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() == payload, \
        "noncanonical native observation JSON"
    replacement_observation_shape(observation)
    return observation, line


def native_replacement_proof(before, frozen, request, native):
    replacement_observation_shape(native)
    old = lifecycle_owner(before)
    expected = {"operation_id": request["operationUUID"], "predecessor": before["currentService"]}
    observation = native["observation"]
    assert observation["request"] == expected == frozen["pendingService"]["request"]
    assert observation["request"] == frozen["serviceReplacement"]["configuration"]["reopen"]["request"]
    assert native["predecessorWorkerUUID"] == old["workerUUID"] == frozen["pendingService"]["predecessorWorkerUUID"]
    previous, successor = before["currentService"], observation["successor"]
    assert successor["grant"] == previous["grant"]
    assert successor["boot"]["identity"] == before["identity"]
    assert successor["boot"]["bootstrap_key"] == previous["boot"]["bootstrap_key"]
    assert successor["context"]["service_epoch"] != old["serviceEpoch"]
    for field in ("controller_epoch", "controller_key"):
        assert successor["context"][field] == previous["context"][field], "native cut changed controller"
    for field in ("tls_root_sha256", "server_spki"):
        assert successor["boot"][field] != previous["boot"][field], "native cut requires fresh TLS"
    assert successor["open_revision"] > previous["open_revision"]


def pending_replacement_artifacts(queue, validate, request, raw, marker, seen=None):
    """A departed task cannot truthfully publish a succeeded queue receipt."""
    validate()
    stem = request["operationUUID"]
    expected = {stem + suffix for suffix in (".request.json", ".pending.json")}
    names = set()
    with os.scandir(queue) as entries:
        for entry in entries:
            assert len(names) < 81, "replacement queue entry bound"
            names.add(entry.name)
    assert names == expected, "departed replacement must remain pending, without synthetic success/failure"
    current = {name: replacement.queue_file(queue, name, 512 if name.endswith(".request.json") else 1048576)
               for name in expected}
    claimed, stamp = current[stem + ".request.json"]
    assert claimed == raw and stamp[:2] == marker, "exact owned request claim required"
    assert seen is None or seen == current, "immutable pending artifacts changed"
    pending = json.loads(current[stem + ".pending.json"][0])
    assert set(pending) == {"schema", "counter", "phase", "request", "proof"}
    assert type(pending["schema"]) is int and pending["schema"] == 1
    assert type(pending["counter"]) is int and pending["counter"] == 1
    assert pending["phase"] == "pending" and pending["request"] == request
    return pending, current


def frozen_replacement_proof(before, frozen, pending, request, submitted, observed, native):
    old = lifecycle_owner(before)
    assert request["store"] == before["identity"]["store"] and request["predecessor"] == old
    for field in ("version", "identity", "rootPublicKey", "provenanceReference", "current",
                  "currentService", "currentContext", "observedWorker"):
        assert frozen[field] == before[field], "pre-completion owner changed"
    for field in ("pending", "pendingTakeover", "pendingCold", "adoptionRetry", "sealed", "terminal",
                  "latestServiceConfirmation", "latestServiceRequest", "latestServiceChange"):
        assert frozen.get(field) is None, "replacement must be frozen before ROOT completion"
    assert not frozen["serviceLinks"] and frozen["nativeReplacementAttempted"] is True
    assert frozen["revision"] > before["revision"]
    context = before["currentService"]["context"]
    assert pending["proof"] == {"controllerEpoch": context["controller_epoch"],
                                "controllerKey": context["controller_key"], "rootPublicKey": before["rootPublicKey"]}
    retained = frozen["pendingService"]
    assert set(retained) == {"request", "stageRequestID", "completionRequestID", "predecessorWorkerUUID",
                             "nowUnixSeconds", "lifetimeSeconds"}
    change = {"operation_id": request["operationUUID"], "predecessor": before["currentService"]}
    assert retained["request"] == change and retained["predecessorWorkerUUID"] == old["workerUUID"]
    for field in ("stageRequestID", "completionRequestID"):
        replacement.uuid4(retained[field])
    assert retained["stageRequestID"] != retained["completionRequestID"]
    assert type(retained["nowUnixSeconds"]) is int and submitted <= retained["nowUnixSeconds"] <= observed
    assert type(retained["lifetimeSeconds"]) is int and 0 < retained["lifetimeSeconds"] <= 86400
    authorization = frozen["serviceReplacement"]
    assert set(authorization) == {"predecessor_worker_uuid", "configuration"}
    assert authorization["predecessor_worker_uuid"] == old["workerUUID"]
    configuration = authorization["configuration"]
    assert configuration["action"] == "open" and configuration["root_public_key"] == before["rootPublicKey"]
    assert configuration["signed"]["grant"] == before["currentService"]["grant"]
    assert configuration["reopen"]["request"] == change and configuration["reopen"]["signature"]
    assert configuration["now_unix_seconds"] == retained["nowUnixSeconds"]
    assert configuration["lifetime_seconds"] == retained["lifetimeSeconds"]
    native_replacement_proof(before, frozen, request, native)


def wait_replacement_pause(daemon, path, before, queue, validate, request, raw, marker, submitted, *, timeout=15):
    deadline = time.monotonic() + timeout
    while True:
        validate()
        assert daemon.process.poll() is None, "daemon exited before replacement cut"
        pause = replacement_pause_observation(daemon)
        if pause is not None:
            frozen, stamp = replacement.read_public(path)
            pending, seen = pending_replacement_artifacts(queue, validate, request, raw, marker)
            frozen_replacement_proof(before, frozen, pending, request, submitted, int(time.time()), pause[0])
            return frozen, stamp, seen, pause
        assert time.monotonic() < deadline, "native replacement cut deadline"
        time.sleep(0.05)


def recovered_replacement_proof(before, frozen, after, request, native):
    """Join the saved actual-native cut to recovery, not compactable HOST history."""
    native_replacement_proof(before, frozen, request, native)
    old, new = lifecycle_owner(before), lifecycle_owner(after)
    for field in ("identity", "rootPublicKey", "provenanceReference"):
        assert after[field] == before[field], "ROOT/store/G changed"
    assert after["revision"] > frozen["revision"]
    for field in old:
        assert new[field] != old[field], "fresh E and worker required"
    for field in ("latestServiceRequest", "latestServiceConfirmation", "latestServiceChange",
                  "serviceReplacement", "nativeReplacementAttempted"):
        assert after.get(field) is None, "takeover must clear pre-takeover latest operation"
    previous, current = before["currentService"], after["currentService"]
    change = {"operation_id": request["operationUUID"], "predecessor": previous}
    assert frozen["pendingService"]["request"] == change
    assert frozen["serviceReplacement"]["configuration"]["reopen"]["request"] == change
    assert frozen["pendingService"]["predecessorWorkerUUID"] == old["workerUUID"]
    observed = native["observation"]["successor"]
    assert current["boot"] == observed["boot"], "recovery rotated the native cut E/TLS"
    assert current["open_revision"] == observed["open_revision"]
    assert new["workerUUID"] == native["workerUUID"], "recovery replaced the native cut worker again"
    assert current["context"]["controller_epoch"] == previous["context"]["controller_epoch"] + 1
    assert current["context"]["controller_key"] != previous["context"]["controller_key"]
    grant = current["grant"]
    assert grant["operation"] == "takeover" and grant["expected_epoch"] == previous["context"]["controller_epoch"]
    completed = after["current"]
    assert completed["original"]["signed"]["grant"] == grant
    assert completed["original"]["signed"]["signature"]
    assert completed["original"]["serviceEpoch"] == new["serviceEpoch"]
    assert completed["directResult"]["grant"] == grant
    assert completed["directResult"]["service_epoch"] == new["serviceEpoch"]
    assert type(completed["directResult"]["revision"]) is int
    assert completed["directResult"]["revision"] > current["open_revision"]
    assert completed != before["current"]
    link = {"operationID": change["operation_id"], "predecessor": before["currentContext"],
            "successor": {"serviceEpoch": new["serviceEpoch"],
                          "controllerEpoch": previous["context"]["controller_epoch"],
                          "controllerKey": previous["context"]["controller_key"]},
            "revision": current["open_revision"]}
    assert current == dict(observed, grant=grant, context=current["context"]), "unexpected recovered service fields"
    assert after["serviceLinks"] in ([], [link]), "unexpected historical replacement operation"
    if not after["serviceLinks"]:
        assert all(not (reference.get("recovery") or {}).get("workerHistoryReference")
                   for reference in after["references"]), "referenced replacement history disappeared"


def settled_replacement_proof(after, final):
    # Called only AFTER saved-native-cut correlation passed. Reference-driven
    # history compaction is not another E/worker/TLS change.
    assert lifecycle_owner(final) == lifecycle_owner(after)
    for field in ("identity", "rootPublicKey", "provenanceReference", "current", "currentService"):
        assert final[field] == after[field], "recovered identity/service changed during fresh DATA"
    assert final["revision"] >= after["revision"]
    for field in ("latestServiceRequest", "latestServiceConfirmation", "latestServiceChange",
                  "serviceReplacement", "nativeReplacementAttempted"):
        assert final.get(field) is None, "unexpected new replacement operation"
    assert final["serviceLinks"] == after["serviceLinks"] or not final["serviceLinks"], "replacement history changed"
    if not final["serviceLinks"]:
        assert all(not (reference.get("recovery") or {}).get("workerHistoryReference")
                   for reference in final["references"]), "referenced replacement history disappeared"


@pytest.mark.compat("RTM-121")
def test_lifecycle_v2_daemon_death_during_worker_replacement(client, daemon, shared):
    from test_managed_storage_recovery import parent_deadline
    with parent_deadline(time.monotonic() + 180):
        disk_baseline = replacement.disk_budget(daemon.root)["allocated"]
        peers = [create_peer(client, shared, name) for name in ("left", "right")]
        for peer in peers:
            peer.start()
            mount_proof(daemon, peer)
        seed = "replacement-crash-seed-" + uuid.uuid4().hex
        exchange(peers[0], peers[1], seed)
        for peer, side in zip(peers, ("left", "right")):
            _exec(peer, "sh", "-ec", f"cp /data/{side} /data/seed-{side}; sync")
        for peer in peers:
            for side in ("left", "right"):
                assert _exec(peer, "cat", "/data/seed-" + side) == (seed + "-" + side).encode()
        ids = {peer.id for peer in peers}
        native = native_snapshot(daemon, ids)
        census = compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
        workloads = [next(p for p in census if p.pid == native[id]["native"][0]) for id in ids]
        api = _kernel_process(daemon.process.pid)
        assert api is not None and api.identity is not None and api.pidversion is not None
        binary = daemon.binary
        root = daemon.root.stat()
        disk = disk_identity(daemon.root)
        path = daemon.root / "managed-storage-owner/state.json"
        before, _ = replacement.read_public(path)
        scope = lifecycle_owner(before)
        assert not before["serviceLinks"] and before.get("latestServiceChange") is None
        assert replacement_pause_observation(daemon) is None
        request, raw = replacement.worker_request(str(uuid.uuid4()), before["identity"]["store"], scope)
        with replacement.replacement_queue(daemon.root, {"device": root.st_dev, "inode": root.st_ino}) as (queue, validate):
            assert native_snapshot(daemon, ids) == native
            replacement.disk_budget(daemon.root, disk_baseline)
            submitted = int(time.time())
            marker = replacement.publish_worker_request(queue, raw)
            frozen, stamp, seen, pause = wait_replacement_pause(
                daemon, path, before, queue, validate, request, raw, marker, submitted)
            assert _kernel_process(api.pid) == api
            daemon.stop(kill=True)  # Only this exact owned daemon, never helper/shim/worker.
            assert daemon.process.poll() == -9
            assert replacement.exact_exit(api, _kernel_process(api.pid))
            assert replacement.read_public(path) == (frozen, stamp), "HOST freeze changed before death"
            assert replacement_pause_observation(daemon) == pause, "native cut marker changed after death"
            # The replaced worker has closed old-E DATA; workloads may already
            # be failed. Only the storage VM must remain running here. Actual
            # old workload exit and Docker 137 are still required below.
            assert native_snapshot(daemon, set()) == {"storage": native["storage"]}
            pending_replacement_artifacts(queue, validate, request, raw, marker, seen)
            daemon.start()  # Same compiled binary; normal recovery bypasses the one normal-operation hook.
            # HOST may already have compacted service history. The saved native
            # observation, not retained latest fields, pins this exact successor.
            after, _ = replacement.read_public(path)
            recovered_replacement_proof(before, frozen, after, request, pause[0])
            assert replacement_pause_observation(daemon) == pause, "native cut changed during recovery"
            assert daemon.binary == binary and client.ping()
            fresh_api = _kernel_process(daemon.process.pid)
            assert fresh_api is not None and fresh_api.identity is not None and fresh_api.pidversion is not None
            assert fresh_api != api and daemon.process.poll() is None
            for process in workloads:
                wait_for_value(lambda: replacement.exact_exit(process, _kernel_process(process.pid)),
                               bool, timeout=30, description="actual old workload native exit after replacement recovery")
            for peer in peers:
                assert peer.wait(timeout=30)["StatusCode"] == 137
                peer.reload()
                assert peer.attrs["State"]["Running"] is False and peer.attrs["State"]["ExitCode"] == 137
            assert native_snapshot(daemon, set()) == {"storage": native["storage"]}
            assert {p.pid for p in compatibility_runtime_processes(daemon.owner_binary, roots=(daemon.root,))
                    if len(p.arguments) > 1 and p.arguments[1] == "vm-shim"} == {native["storage"]["native"][0]}, \
                "unexpected workload VM survived replacement recovery"
            pending_replacement_artifacts(queue, validate, request, raw, marker, seen)
            replacement.disk_budget(daemon.root, disk_baseline)
            fresh = [create_peer(client, shared, name) for name in ("fresh-left", "fresh-right")]
            for peer in fresh:
                peer.start()
                mount_proof(daemon, peer)
                for side in ("left", "right"):
                    assert _exec(peer, "cat", "/data/seed-" + side) == (seed + "-" + side).encode()
            exchange(fresh[0], fresh[1], "replacement-recovered-" + uuid.uuid4().hex)
            assert native_snapshot(daemon, {peer.id for peer in fresh})["storage"] == native["storage"]
            assert (daemon.root.stat().st_dev, daemon.root.stat().st_ino) == (root.st_dev, root.st_ino)
            assert disk_identity(daemon.root) == disk and _kernel_process(fresh_api.pid) == fresh_api
            final, _ = replacement.read_public(path)
            settled_replacement_proof(after, final)
            assert replacement_pause_observation(daemon) == pause, "native cut changed or recovery repeated the pause"
            pending_replacement_artifacts(queue, validate, request, raw, marker, seen)
            validate()
            replacement.disk_budget(daemon.root, disk_baseline)


def takeover_observation_shape(value):
    """Closed public cut receipt; deliberately never an engine input."""
    assert type(value) is dict and set(value) == {"grant", "serviceEpoch", "workerUUID", "openRevision"}
    for field in ("serviceEpoch", "workerUUID"):
        replacement.uuid4(value[field])
    assert type(value["openRevision"]) is int and 0 < value["openRevision"] < 2**64
    grant = value["grant"]
    assert type(grant) is dict and set(grant) == {"operation", "id", "identity", "serial", "expected_epoch", "new_key"}
    assert grant["operation"] == "takeover"
    replacement.uuid4(grant["id"])
    for field in ("serial", "expected_epoch"):
        assert type(grant[field]) is int and 0 < grant[field] < 2**64
    assert grant["expected_epoch"] < 2**64 - 1
    identity = grant["identity"]
    assert type(identity) is dict and set(identity) == {"store", "generation", "binding"}
    replacement.uuid4(identity["store"])
    assert type(identity["generation"]) is int and 0 < identity["generation"] < 2**64
    for value in (identity["binding"], grant["new_key"]):
        assert type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)


def takeover_pause_observation(daemon, profile, previous=0):
    assert profile in TAKEOVER_FAULTS and type(previous) is int and 0 <= previous < 2
    with daemon.log_path.open("rb") as stream:
        data = stream.read(1048577)
    assert len(data) <= 1048576, "daemon diagnostic log exceeded bound"
    marker = ("cengine.compat.lifecycle." + profile + ".paused").encode()
    lines = [line for line in data.splitlines(keepends=True) if b"takeover-apply-v1.paused" in line]
    assert len(lines) <= previous + 1, "unexpected repeated takeover fault"
    if len(lines) <= previous:
        return None
    line = lines[-1]
    assert line.startswith(marker + b" "), "wrong takeover cut"
    if not line.endswith(b"\n"):
        return None
    payload = line[len(marker) + 1:-1]
    assert 0 < len(payload) <= 8192
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, "duplicate takeover observation key"
            result[key] = value
        return result
    value = json.loads(payload, object_pairs_hook=unique)
    takeover_observation_shape(value)
    assert json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() == payload
    return value, line


def frozen_takeover_proof(before, frozen, observation):
    takeover_observation_shape(observation)
    old = lifecycle_owner(before)
    grant = observation["grant"]
    assert frozen["pending"]["signed"]["grant"] == grant
    assert frozen["pending"]["serviceEpoch"] == observation["serviceEpoch"] == old["serviceEpoch"]
    assert observation["workerUUID"] == old["workerUUID"]
    assert observation["openRevision"] == before["currentService"]["open_revision"]
    for field in ("identity", "rootPublicKey", "current", "currentContext", "currentService", "contexts"):
        assert frozen[field] == before[field], "takeover cut changed predecessor"
    for field in ("pendingTakeover", "pendingService", "pendingCold", "handoffRetry", "sealed", "terminal"):
        assert frozen.get(field) is None
    prior = before["currentService"]["grant"]
    assert grant["identity"] == before["identity"]
    assert grant["expected_epoch"] == before["currentContext"]["controllerEpoch"]
    assert grant["serial"] == prior["serial"] + 1
    assert grant["id"] != prior["id"] and grant["new_key"] != prior["new_key"]
    assert frozen["revision"] > before["revision"]


def recovered_takeover_proof(before, frozen, after, observation, profile):
    assert profile in TAKEOVER_FAULTS
    frozen_takeover_proof(before, frozen, observation)
    assert lifecycle_owner(after) == lifecycle_owner(before)
    for field in ("identity", "rootPublicKey", "provenanceReference"):
        assert after[field] == before[field]
    assert after.get("handoffRetry") is None
    previous, current = before["currentService"], after["currentService"]
    assert current["boot"] == previous["boot"] and current["open_revision"] == previous["open_revision"]
    abandoned, successor = observation["grant"], current["grant"]
    # Aborted issuance still consumes its serial; C advances only if it applied.
    expected_epoch = abandoned["expected_epoch"] + (profile == TAKEOVER_FAULTS[1])
    assert successor["expected_epoch"] == expected_epoch
    assert successor["serial"] == abandoned["serial"] + 1, "abandoned serial high-water was reused"
    assert successor["id"] not in (abandoned["id"], previous["grant"]["id"])
    assert successor["new_key"] not in (abandoned["new_key"], previous["grant"]["new_key"])
    assert after["current"]["original"]["signed"]["grant"] == successor
    assert after["current"]["directResult"]["grant"] == successor
    # Historical grants still referenced by original live peers must stay exact.
    referenced = [reference["original"] for reference in before["references"]]
    for context in before["contexts"]:
        if context["context"] in referenced:
            assert context in after["contexts"], "live peer's historical grant was lost"
    assert after["revision"] > frozen["revision"]


@pytest.mark.compat("RTM-125")
def test_lifecycle_v2_interrupted_live_takeover_recovers(client, daemon, shared):
    from test_managed_storage_recovery import parent_deadline
    profile = os.environ.get(FAULT_ENV)
    assert profile in TAKEOVER_FAULTS
    with parent_deadline(time.monotonic() + 240):
        peers = [create_peer(client, shared, name, progress_command(name, other))
                 for name, other in (("left", "right"), ("right", "left"))]
        for peer in peers:
            peer.start()
            mount_proof(daemon, peer)
        ids = {peer.id for peer in peers}
        native = native_snapshot(daemon, ids)
        binary, disk = daemon.binary, disk_identity(daemon.root)
        root = daemon.root.stat()
        budget = replacement.disk_budget(daemon.root)["allocated"]
        path = daemon.root / "managed-storage-owner/state.json"
        assert takeover_pause_observation(daemon, profile) is None
        for repeat in range(2):
            exchange(peers[0], peers[1], "takeover-before-" + uuid.uuid4().hex)
            before, _ = replacement.read_public(path)
            lifecycle_owner(before)
            baseline = {}
            for name, peer in zip(("left", "right"), peers):
                baseline[name] = wait_for_value(lambda: parse_progress(peer.logs(), name),
                    lambda row: row is not None and row[1] > 1, timeout=20,
                    description="both original open-unlinked peers progressing")
            clocks = {}
            for name, peer in zip(("left", "right"), peers):
                sampled_at = time.monotonic()
                clocks[name] = (sampled_at, float(_exec(peer, "cat", "/proc/uptime").split()[0]))
            daemon.stop(kill=True)
            assert daemon.process.poll() == -9
            cut = {}
            def qualify(paused):
                assert paused is daemon and paused.process.poll() is None
                pause = wait_for_value(lambda: takeover_pause_observation(paused, profile, repeat),
                    lambda value: value is not None, timeout=15, description="sealed takeover cut")
                frozen, stamp = replacement.read_public(path)
                frozen_takeover_proof(before, frozen, pause[0])
                assert native_snapshot(daemon, ids) == native
                child = _kernel_process(paused.process.pid)
                assert child is not None and child.identity is not None and child.pidversion is not None
                paused.stop(kill=True)  # Actual Popen child, never ROOT/worker/shim.
                assert paused.process.poll() == -9
                assert replacement.exact_exit(child, _kernel_process(child.pid))
                assert replacement.read_public(path) == (frozen, stamp)
                killed_at = time.monotonic()
                for name, peer in zip(("left", "right"), peers):
                    first = spool_progress(daemon, native[peer.id], name)
                    baseline[name] = wait_for_value(lambda: spool_progress(daemon, native[peer.id], name),
                        lambda row: progressed(first, row) and produced_while_absent(row, clocks[name], killed_at),
                        timeout=20, description="original unlinked FD and peer DATA after paused daemon death")
                assert takeover_pause_observation(daemon, profile, repeat) == pause
                cut.update(frozen=frozen, pause=pause)
                return True
            daemon.start(qualify_lifecycle_fault=qualify)
            assert cut and daemon.process.poll() == -9
            daemon.start()  # Same signed binary; authenticated recoverHandoff bypasses this owner's hook.
            after, _ = replacement.read_public(path)
            recovered_takeover_proof(before, cut["frozen"], after, cut["pause"][0], profile)
            assert daemon.binary == binary and client.ping()
            assert native_snapshot(daemon, ids) == native and disk_identity(daemon.root) == disk
            assert (daemon.root.stat().st_dev, daemon.root.stat().st_ino) == (root.st_dev, root.st_ino)
            assert takeover_pause_observation(daemon, profile, repeat) == cut["pause"]
            for name, peer in zip(("left", "right"), peers):
                peer.reload()
                assert peer.status == "running" and peer.attrs["RestartCount"] == 0
                mount_proof(daemon, peer)
                wait_for_value(lambda: parse_progress(peer.logs(), name),
                    lambda row: progressed(baseline[name], row), timeout=30,
                    description="original unlinked FD and bidirectional progress after interrupted takeover")
            exchange(peers[0], peers[1], "takeover-recovered-" + uuid.uuid4().hex)
            final, _ = replacement.read_public(path)
            recovered_takeover_proof(before, cut["frozen"], final, cut["pause"][0], profile)
            assert takeover_pause_observation(daemon, profile, repeat) == cut["pause"]
            replacement.disk_budget(daemon.root, budget)
