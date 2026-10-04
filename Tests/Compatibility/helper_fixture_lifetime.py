"""Test-process isolation only. Never clean roots, signal clients, or install helpers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile

import harness

SERVICE = "dev.cengine.network-helper.test-compat"
TOKEN = f"/Library/Application Support/cengine/compat/{SERVICE}/client-token"


def canonical_temp() -> Path:
    result = subprocess.run(["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"],
                            check=True, capture_output=True, text=True, timeout=5)
    value = Path(result.stdout.strip())
    if not value.is_absolute() or not value.is_dir():
        raise RuntimeError("canonical compatibility temporary directory unavailable")
    return value.resolve(strict=True)


def canonical_lock() -> Path:
    # Independent of HOME, checkout, CENGINE_COMPAT_LOCK and TMPDIR.
    return Path("/private/tmp") / f"cengine-compat-run-{os.getuid()}.lock"


def launcher_lock() -> Path:
    expected = canonical_lock()
    if Path.home().resolve() != Path(pwd.getpwuid(os.getuid()).pw_dir).resolve():
        raise RuntimeError("HOME must be the current UID's canonical home")
    if ("CENGINE_COMPAT_LOCK" in os.environ
            and Path(os.environ["CENGINE_COMPAT_LOCK"]).absolute() != expected):
        raise RuntimeError("CENGINE_COMPAT_LOCK must be the canonical owner lock")
    if Path(tempfile.gettempdir()).resolve() != canonical_temp():
        raise RuntimeError("TMPDIR must be the macOS user temporary directory")
    return expected


def claim_identity() -> tuple[int, ...]:
    """Snapshot only our freshly published claim; never adopt a replacement."""
    lock = launcher_lock()
    owner = os.environ.get("CENGINE_COMPAT_OWNER_PID", "")
    if not owner.isdigit() or int(owner) <= 1:
        raise RuntimeError("invalid invoking runner PID")
    directory = os.open(lock, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise RuntimeError("unsafe invoking runner claim")
        pid = os.open("pid", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            pidinfo = os.fstat(pid)
            if (not stat.S_ISREG(pidinfo.st_mode) or pidinfo.st_uid != os.getuid()
                    or stat.S_IMODE(pidinfo.st_mode) != 0o600 or pidinfo.st_nlink != 1
                    or os.read(pid, 64) != (owner + "\n").encode()):
                raise RuntimeError("unsafe invoking runner PID file")
            visible_pid = os.stat("pid", dir_fd=directory, follow_symlinks=False)
            visible = lock.lstat()
            if ((visible.st_dev, visible.st_ino) != (info.st_dev, info.st_ino)
                    or (visible_pid.st_dev, visible_pid.st_ino, visible_pid.st_ctime_ns)
                    != (pidinfo.st_dev, pidinfo.st_ino, pidinfo.st_ctime_ns)
                    or os.fstat(pid).st_ctime_ns != pidinfo.st_ctime_ns):
                raise RuntimeError("invoking runner claim changed during inspection")
            process = harness._kernel_process(int(owner))
            if process is None or process.identity is None or process.pidversion is None:
                raise RuntimeError("invoking runner process identity unavailable")
            # A surviving pytest child must not mistake numeric PID reuse for its
            # original launcher. The kernel reader brackets argv with birth identity.
            return (info.st_dev, info.st_ino, pidinfo.st_dev, pidinfo.st_ino,
                    pidinfo.st_ctime_ns, int(owner), *process.identity, process.pidversion)
        finally:
            os.close(pid)
    finally:
        os.close(directory)


def require_claim() -> tuple[int, ...]:
    identity = claim_identity()
    if os.environ.get("CENGINE_COMPAT_CLAIM") != json.dumps(identity):
        raise RuntimeError("invoking runner claim differs from its publication receipt")
    return identity


def release_claim() -> None:
    identity = require_claim()
    lock = launcher_lock()
    directory = os.open(lock, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if (info.st_dev, info.st_ino) != identity[:2] or os.listdir(directory) != ["pid"]:
            raise RuntimeError("refusing changed or nonempty invoking runner claim")
        require_claim()
        os.unlink("pid", dir_fd=directory)
        visible = lock.lstat()
        if (visible.st_dev, visible.st_ino) != identity[:2]:
            raise RuntimeError("invoking runner claim changed during release")
        lock.rmdir()  # Never recursively delete a claim or unknown entries.
    finally:
        os.close(directory)


def require_no_roots() -> None:
    parents = {canonical_temp(), Path("/private/tmp"),
               Path.home() / "Library/Caches/cengine-compat-matrix"}
    for parent in parents:
        try:
            if parent.is_symlink():
                raise RuntimeError("unknown compatibility root parent")
            entries = list(parent.iterdir())
        except FileNotFoundError:
            if parent.name == "cengine-compat-matrix":
                continue
            raise
        for entry in entries:
            # Installer staging is not a runtime work root. Recognize only its
            # reserved name and closed regular-file layout; never read its token
            # or remove it. Anything containing runtime state still refuses.
            if re.fullmatch(r"cengine-compat-helper\.[A-Za-z0-9]{6}", entry.name):
                info = entry.lstat()
                if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid():
                    files = list(entry.iterdir())
                    if ({file.name for file in files} == {"manifest", "helper.plist", "client-token"}
                            and all(stat.S_ISREG(file.lstat().st_mode)
                                    and file.lstat().st_uid == os.getuid() for file in files)):
                        continue
            if entry.name.startswith("cengine-compat-") and entry != canonical_lock():
                # Even an empty/unowned/symlink root is uncertainty, not disposal authority.
                raise RuntimeError(f"helper isolation refused a retained or unknown compatibility root: {entry}")


def require_no_clients() -> None:
    # ps enumerates IDs only. Kernel argv inspection is read-only and fails closed.
    table = subprocess.run(["/bin/ps", "-axo", "pid=,uid="], check=True,
                           capture_output=True, text=True, timeout=5).stdout
    owner = int(os.environ["CENGINE_COMPAT_OWNER_PID"])
    seen_owner = False
    for line in table.splitlines():
        fields = line.split()
        if (len(fields) != 2 or not fields[0].isdigit()
                or re.fullmatch(r"-?[0-9]+", fields[1]) is None):
            raise RuntimeError("ambiguous process census")
        pid, uid = map(int, fields)
        if pid <= 0 or not -(2**31) <= uid < 2**32:
            raise RuntimeError("ambiguous process census")
        # Darwin ps prints some uid_t values as signed integers (nobody = -2).
        # Normalize the fixed-width UID before selecting this runner's clients.
        uid &= 0xffffffff
        if uid != os.getuid():
            continue
        seen_owner |= pid == owner
        if not harness._kernel_process_argv_excludes_runtime(pid):
            raise RuntimeError("helper isolation refused an active or unknown runtime client")
    if not seen_owner:
        raise RuntimeError("invoking runner disappeared")


def validate_status(value: object) -> dict:
    fingerprint = os.environ.get("CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT", "")
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        raise RuntimeError("installed helper fingerprint missing")
    if not isinstance(value, dict):
        raise RuntimeError("invalid helper status")
    expected = dict(serviceName=SERVICE, buildFingerprint=fingerprint,
                    ownerUID=os.getuid(), protocolVersion=5)
    if any(value.get(key) != expected_value or type(value.get(key)) is not type(expected_value)
           for key, expected_value in expected.items()):
        raise RuntimeError("unexpected installed test helper identity")
    caps = value.get("capabilities")
    if (type(value.get("processIdentifier")) is not int or value["processIdentifier"] <= 0
            or not isinstance(caps, dict) or caps.get("profile") != "ordinary"
            or "lifecycle-v2" not in caps.get("storageContracts", [])):
        raise RuntimeError("unexpected test helper process or capabilities")
    # The signed --require-managed client enforces the complete compiled capability
    # and security floor; this is an additional identity check, not a replacement.
    return value


def restart_before_fixture(binary: Path) -> None:
    expected_environment = {
        "CENGINE_NETWORK_HELPER_SERVICE_NAME": SERVICE,
        "CENGINE_NETWORK_HELPER_IDENTIFIER": SERVICE,
        "CENGINE_COMPAT_NETWORK_HELPER_LABEL": SERVICE,
        "CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE": TOKEN,
    }
    if any(os.environ.get(key) != value for key, value in expected_environment.items()):
        raise RuntimeError("helper isolation requires the exact test namespace")
    claim = require_claim()
    require_no_roots()
    require_no_clients()

    def command(*arguments: str, timeout: int) -> dict:
        result = subprocess.run([str(binary), "helper", *arguments], check=True,
                                capture_output=True, text=True, timeout=timeout)
        return validate_status(json.loads(result.stdout))

    before = command("status", "--require-managed", "lifecycle-v2", timeout=10)
    # Recheck after authentication, immediately before the single mutating request.
    if require_claim() != claim:
        raise RuntimeError("helper isolation claim changed")
    require_no_roots()
    require_no_clients()
    restarted = command("restart", timeout=45)
    after = command("status", "--require-managed", "lifecycle-v2", timeout=10)
    if (after["processIdentifier"] == before["processIdentifier"]
            or restarted != after
            or {k: v for k, v in before.items() if k != "processIdentifier"}
            != {k: v for k, v in after.items() if k != "processIdentifier"}
            or require_claim() != claim):
        raise RuntimeError("helper restart did not prove a new process with unchanged identity")
    # A successful status is not proof that no unexpected client forked meanwhile.
    require_no_roots()
    require_no_clients()
    if require_claim() != claim:
        raise RuntimeError("helper isolation claim changed after final census")


def restart_for_offline_remount(transaction) -> None:
    """RTM-126 only: release helper ROOT FDs after a joined, drained child.

    This is deliberately not an allowlist parameter on the ordinary fixture
    boundary. Its sole exception is the original fixed-work remount transaction;
    every other compatibility root (including installer staging) refuses.
    """
    from storage_lifecycle_v2_remount import OfflineRemount
    if type(transaction) is not OfflineRemount or transaction.restart_pending:
        raise RuntimeError("invalid or previously refused offline remount transaction")
    transaction.restart_pending = True  # A failed boundary must never be retried.
    expected = {
        "CENGINE_NETWORK_HELPER_SERVICE_NAME": SERVICE,
        "CENGINE_NETWORK_HELPER_IDENTIFIER": SERVICE,
        "CENGINE_COMPAT_NETWORK_HELPER_LABEL": SERVICE,
        "CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE": TOKEN,
    }
    if any(os.environ.get(key) != value for key, value in expected.items()):
        raise RuntimeError("offline remount requires exact test helper namespace")
    claim = require_claim()

    def guard():
        if require_claim() != claim:
            raise RuntimeError("offline remount runner claim changed")
        transaction.validate_boundary()
        parents = {canonical_temp(), Path("/private/tmp"),
                   Path.home() / "Library/Caches/cengine-compat-matrix"}
        for parent in parents:
            if parent.is_symlink():
                raise RuntimeError("unknown compatibility root parent")
            try:
                entries = list(parent.iterdir())
            except FileNotFoundError:
                if parent.name == "cengine-compat-matrix":
                    continue
                raise
            for entry in entries:
                if (entry.name.startswith("cengine-compat-")
                        and entry not in (canonical_lock(), transaction.value.work)):
                    raise RuntimeError("offline remount refused competing compatibility root")
        require_no_clients()

    def command(*arguments, timeout):
        result = subprocess.run([str(transaction.value.binary), "helper", *arguments],
                                check=True, capture_output=True, text=True, timeout=timeout)
        status = validate_status(json.loads(result.stdout))
        if "lifecycle-v2-stable-host-identity-v1" not in status["capabilities"]["storageContracts"]:
            raise RuntimeError("offline remount requires the updated installed test helper")
        return status

    guard()
    before = command("status", "--require-managed", "lifecycle-v2", timeout=10)
    guard()
    restarted = command("restart", timeout=45)
    after = command("status", "--require-managed", "lifecycle-v2", timeout=10)
    if (after["processIdentifier"] == before["processIdentifier"] or restarted != after
            or {k: v for k, v in before.items() if k != "processIdentifier"}
            != {k: v for k, v in after.items() if k != "processIdentifier"}):
        raise RuntimeError("offline remount helper restart identity mismatch")
    guard()
    transaction.restart_pending = False
    transaction.helper_released = True


class FixtureBoundary:
    """A failed/ambiguous boundary is terminal for this pytest process; no retry."""
    def __init__(self):
        self.previous = None
        self.pending = False

    def prepare(self, binary: Path) -> None:
        if self.pending or (self.previous is not None and (
                self.previous._managed_fixture_retention or self.previous._retain_root
                or os.path.lexists(self.previous.work))):
            raise RuntimeError("previous fixture was not finalized and removed")
        self.pending = True
        restart_before_fixture(binary)

    def created(self, value) -> None:
        self.previous = value
        self.pending = False


def main(arguments: list[str]) -> None:
    try:
        if not arguments:
            print(launcher_lock())
        elif (len(arguments) == 2 and arguments[1] == os.environ.get("CENGINE_COMPAT_OWNER_PID")
              and arguments[0] in ("pin-claim", "verify-claim", "release-claim")):
            if arguments[0] == "pin-claim":
                print(json.dumps(claim_identity()))
            elif arguments[0] == "verify-claim":
                require_claim()
            else:
                release_claim()
        else:
            raise RuntimeError("invalid runner claim operation")
    except Exception:
        sys.exit("compatibility runner claim unavailable or changed; no cleanup authorized")


if __name__ == "__main__":
    main(sys.argv[1:])
