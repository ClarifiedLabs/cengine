"""Closed signed lifecycle candidate: RTM-114/115/116, native acceptance pending.

Only an absent/empty explicit profile skips these tests in the ordinary suite.
An opted-in run fails on missing prerequisites. The normal runner owns the
installed-helper guard; the compiled driver authenticates signed metadata/assets.
No ordinary Docker daemon, image cache, receipt-file input or generic shim kill.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time
import uuid

import pytest

from harness import (
    COMPATIBILITY_OWNER_FILE, RuntimeProcess, _kernel_process,
    _kernel_process_argv_excludes_runtime, _signal_runtime_process,
    compatibility_environment, compatibility_runtime_processes,
    preretain_compatibility_root, retain_compatibility_root,
)

PROFILE = "lifecycle-v2-native-v1"
PROFILE_ENV = "CENGINE_STORAGE_LIFECYCLE_QUALIFICATION"
CASES = ("fresh", "lost-completion", "live-proof-loss")
SHIM = "--storage-lifecycle-qualification-shim"
BUDGET_SECONDS = 240


@pytest.fixture(autouse=True)
def verify_docker_cli_target():
    # Override conftest's daemon/client dependency, including before opt-in checks.
    pass


@pytest.fixture(autouse=True)
def daemon_survived():
    # The qualification process owns its own signed native children, not Daemon.
    pass


def prerequisites(environment):
    profile = environment.get(PROFILE_ENV, "")
    if not profile:
        pytest.skip(f"native lifecycle cases are inapplicable without {PROFILE_ENV}={PROFILE}")
    if profile != PROFILE:
        raise ValueError("unknown lifecycle qualification profile")
    for key in ("CENGINE_COMPAT_MANAGED_STORAGE", "CENGINE_COMPAT_SHARED_STORAGE"):
        if key in environment:
            raise ValueError("retired native lifecycle startup selector")
    if environment.get("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY") or environment.get("PREPARE_COMPATIBILITY_PROFILE"):
        raise ValueError("lifecycle qualification cannot combine PREPARE profiles")
    paths = []
    for name in ("CENGINE_BINARY", "CENGINE_COMPAT_MANAGED_ASSET_DIR"):
        raw = environment.get(name, "")
        if not raw or not Path(raw).is_absolute():
            raise ValueError(f"{name} must explicitly name an absolute path")
        paths.append(Path(raw).resolve(strict=True))
    binary, assets = paths
    if not binary.is_file() or not os.access(binary, os.X_OK) or not assets.is_dir():
        raise ValueError("native qualification binary/assets unavailable")
    controller = binary.with_name("cengine-storage-controller")
    if not controller.is_file() or not os.access(controller, os.X_OK):
        raise ValueError("paired native controller unavailable")
    for name in ("vmlinux", "storage-initramfs.cpio.gz", "disk-bootstrap.json", "SHA256SUMS"):
        if not (assets / name).is_file():
            raise ValueError("native qualification assets incomplete")
    # No Python metadata value authorizes boot. This exact driver entry exists
    # only in the qualification build and validates signed profile/pins itself.
    return binary, assets


def command(binary, root, assets, case):
    if case not in CASES:
        raise ValueError("unknown native lifecycle case")
    return [str(binary), "storage-lifecycle-qualification", "--root", str(root),
            "--assets", str(assets), "--case", case]


def receipt(stdout: bytes, case: str):
    if case not in CASES or not stdout or len(stdout) > 1024 * 1024:
        raise ValueError("missing or oversized native receipt")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate native receipt field")
            result[key] = value
        return result
    value = json.loads(stdout.decode("utf-8").splitlines()[-1], object_pairs_hook=unique)
    if not isinstance(value, dict) or value.get("profile") != PROFILE or value.get("case") != case:
        raise ValueError("native receipt selection mismatch")
    expected = dict(success=True, hostReopened=True, rootAuthenticated=True,
                    shimReaped=True, controllerReaped=True, terminal=case != "live-proof-loss")
    if case == "lost-completion":
        expected.update(replyDropped=True, stableGrant=True, freshProof=True)
    if case == "live-proof-loss":
        expected.update(proofRefused=True, pendingPreserved=True, liveShimObserved=True)
    allowed = set(expected) | {"profile", "case", "generation", "store", "publicIDs", "digests"}
    if set(value) - allowed:
        raise ValueError("unexpected native receipt assertion")
    for field in ("publicIDs", "digests"):
        optional = value.get(field, {})
        if not isinstance(optional, dict) or not all(isinstance(item, str) for item in optional.values()):
            raise ValueError("invalid optional public metadata")
        for item in optional.values():
            if field == "publicIDs":
                if uuid.UUID(item).int == 0:
                    raise ValueError("invalid optional public UUID")
            elif len(item) != 64 or any(char not in "0123456789abcdef" for char in item):
                raise ValueError("invalid optional public digest")
    if any(value.get(key) is not wanted for key, wanted in expected.items()):
        raise ValueError("native case assertions incomplete")
    if type(value.get("generation")) is not int or value["generation"] != 1:
        raise ValueError("native fresh generation mismatch")
    if not isinstance(value.get("store"), str) or uuid.UUID(value["store"]).int == 0:
        raise ValueError("native store UUID missing")
    return value


def incarnation(process):
    if process.identity is None or process.pidversion is None:
        raise RuntimeError("native process birth identity unavailable")
    return process.pid, process.identity, process.pidversion


def candidate_processes(binary):
    """Census only; a matching FD3 argv does NOT grant signal authority."""
    controller = binary.with_name("cengine-storage-controller")
    result = []
    table = subprocess.run(["ps", "-axo", "pid=,uid="], check=True, text=True,
                           stdout=subprocess.PIPE, timeout=5).stdout
    for line in table.splitlines():
        fields = line.split()
        if len(fields) != 2 or not all(value.isdigit() for value in fields) or int(fields[1]) != os.getuid():
            continue
        pid = int(fields[0])
        try:
            process = _kernel_process(pid, binary) or _kernel_process(pid, controller)
        except RuntimeError:
            if _kernel_process_argv_excludes_runtime(pid):
                continue
            raise
        if process is None:
            continue
        args = process.arguments
        if (Path(process.executable).resolve() == binary and len(args) >= 2
                and (args[1] == "storage-lifecycle-qualification" or args[1:] == (SHIM,))
                or Path(process.executable).resolve() == controller and args[1:] == ("--lifecycle-v2",)):
            result.append(process)
    return result


@dataclass
class OwnedCensus:
    binary: Path
    baseline: set = field(default_factory=set)
    owned: dict = field(default_factory=dict)

    def before_launch(self):
        self.baseline = {incarnation(value) for value in candidate_processes(self.binary)}

    def observe(self, process):
        if process is None:
            return
        self.owned[incarnation(process)] = process

    def refresh(self):
        values = candidate_processes(self.binary)
        # Child ancestry is kernel PPID + a still-identical observed parent birth,
        # never a ps command substring, receipt PID or bare shim flag.
        for _ in range(len(values) + 1):
            added = False
            for child in values:
                key = incarnation(child)
                if key in self.owned or key in self.baseline:
                    continue
                parent = next((item for item in self.owned.values() if item.pid == child.parent_pid), None)
                if parent is not None:
                    current = _kernel_process(parent.pid)
                    if current is not None and incarnation(current) == incarnation(parent):
                        self.observe(child)
                        added = True
            if not added:
                break
        return values

    def require_empty(self, root):
        values = self.refresh()
        # A newly orphaned shim missed between samples is uncertainty, NOT an
        # adopted child. Preserve the root, and never signal that unknown process.
        if any(incarnation(value) not in self.baseline for value in values):
            raise RuntimeError("native process census is not empty")
        for prior in self.owned.values():
            current = _kernel_process(prior.pid)
            if current is not None and incarnation(current) == incarnation(prior):
                raise RuntimeError("owned native descendant remains live")
        if compatibility_runtime_processes(self.binary, roots=(root,)):
            raise RuntimeError("owned root runtime remains live")

    def contain(self):
        # Exact incarnation signaling only. Unknown/orphan/unrelated processes are
        # evidence for retention, never expanded kill authority. Stop parents first.
        incomplete = False
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                self.refresh()
            except Exception:
                incomplete = True
            for value in list(self.owned.values()):
                try:
                    _signal_runtime_process(value, sig)
                except Exception:
                    incomplete = True
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    values = self.refresh()
                except Exception:
                    incomplete = True
                    break
                if not any(incarnation(value) in self.owned for value in values):
                    if incomplete:
                        raise RuntimeError("native containment census incomplete")
                    return
                time.sleep(0.05)
        if incomplete:
            raise RuntimeError("native containment incomplete")


@dataclass
class NativeQualification:
    owner_binary: Path
    assets: Path
    work: Path
    census: OwnedCensus
    environment: dict[str, str]
    process: subprocess.Popen | None = None
    succeeded: bool = False
    _retain_root: bool = False
    _managed_fixture_retention: bool = True

    @property
    def root(self):
        return self.work / "root"

    def run(self, case):
        argv = command(self.owner_binary, self.root, self.assets, case)
        self.census.before_launch()
        with (self.work / "stdout.log").open("wb") as output, (self.work / "stderr.log").open("wb") as errors:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                            stderr=errors, env=self.environment)
            self.census.observe(_kernel_process(self.process.pid, self.owner_binary))
            deadline = time.monotonic() + BUDGET_SECONDS
            while self.process.poll() is None:
                self.census.refresh()
                if time.monotonic() >= deadline:
                    raise TimeoutError("native qualification deadline")
                time.sleep(0.05)
        if self.process.returncode != 0:
            raise RuntimeError("native qualification driver failed")
        with (self.work / "stdout.log").open("rb") as output:
            result = receipt(output.read(1024 * 1024 + 1), case)
        self.census.require_empty(self.root)
        self.succeeded = True
        return result


@pytest.fixture
def native_qualification(request):
    from conftest import pytest_sessionstart
    try:
        environment = compatibility_environment()
        binary, assets = prerequisites(environment)
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise ValueError("native lifecycle qualification requires Darwin arm64")
        # Reuse the exact run-ID/parent-PID marker guard; no invented fixture owner.
        pytest_sessionstart(request.session)
    except Exception:
        pytest.fail("native lifecycle prerequisites refused; use the signed qualification runner", pytrace=False)
    work = Path(tempfile.mkdtemp(prefix="cengine-compat-"))
    (work / COMPATIBILITY_OWNER_FILE).write_text(f"{binary}\n")
    (work / "root").mkdir(mode=0o700)
    try:
        retention = preretain_compatibility_root(work, binary)
    except Exception:
        pytest.fail(f"native root pre-retention failed: {work}", pytrace=False)
    value = NativeQualification(binary, assets, work, OwnedCensus(binary), environment)
    try:
        yield value
    finally:
        passed = all(getattr(getattr(request.node, f"report_{phase}", None), "passed", False)
                     for phase in ("setup", "call"))
        try:
            if not value.succeeded or not passed:
                value._retain_root = True
                try:
                    retain_compatibility_root(work, binary, reason="unsafe-disk-phase")
                finally:
                    try:
                        value.census.contain()
                    finally:
                        # Popen owns this direct child even if kernel observation
                        # failed before recording its birth. poll/wait brackets
                        # prevent signaling a reaped/reused PID; never a shim PID.
                        if value.process is not None and value.process.poll() is None:
                            value.process.terminate()
                            try:
                                value.process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                value.process.kill()
                                value.process.wait(timeout=5)
            if value.process is not None:
                value.process.wait(timeout=5)
            value.census.require_empty(value.root)
        except Exception:
            value._retain_root = True
            try:
                retain_compatibility_root(work, binary, reason="cleanup-incomplete")
            except Exception:
                pass
            pytest.fail(f"native process cleanup incomplete; root retained: {work}", pytrace=False)
        finally:
            if value._retain_root:
                # No raw argv, receipt, stderr or potential boot secrets in reports.
                print(f"\nnative lifecycle root retained for diagnosis: {work}")
        if value.succeeded and passed and not value._retain_root:
            # Existing conftest hook waits for the final teardown report before
            # releasing the unchanged marker and deleting this disposable root.
            request.node._managed_root_cleanup = (value, retention)


def run_case(value, case):
    try:
        value.run(case)
    except Exception:
        pytest.fail(f"native lifecycle case {case} failed; root retained: {value.work}", pytrace=False)


@pytest.mark.compat("RTM-114")
def test_native_storage_lifecycle_fresh(native_qualification):
    run_case(native_qualification, "fresh")


@pytest.mark.compat("RTM-115")
def test_native_storage_lifecycle_lost_completion(native_qualification):
    run_case(native_qualification, "lost-completion")


@pytest.mark.compat("RTM-116")
def test_native_storage_lifecycle_live_proof_loss(native_qualification):
    run_case(native_qualification, "live-proof-loss")
