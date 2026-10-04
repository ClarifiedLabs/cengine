"""RTM-086 guest-only probe. Importing defines helpers; it never executes a program."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import tempfile

ROOT = Path("/tmp/rtm086")
MAX_BINARY = 1024 * 1024
MAX_OUTPUT = 4096
SCRIPT = b'#!/bin/sh\nprintf "rtm086-script\\n"\n'
# The pinned image's /bin/echo is a BusyBox applet. Keep its executable
# basename: copying it as "elf" execs successfully but reports an unknown applet.
CASES = (("script", []), ("echo", ["rtm086-elf"]),
         ("script-noexec", []), ("echo-noexec", ["rtm086-elf"]))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_bounded(path, maximum):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, "file exceeds probe bound")
    return data


def identity():
    status = read_bounded("/proc/self/status", 65536).decode()
    fields = dict(line.split(":", 1) for line in status.splitlines())
    caps = {key: int(fields[key].strip(), 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    require(os.getresuid() == (10001,) * 3 and os.getresgid() == (10001,) * 3,
            "probe must run as UID/GID 10001")
    require(all(value == 0 for value in caps.values()), "probe has capabilities")
    return {"uid": os.geteuid(), "gid": os.getegid(), "capabilities": caps}


def prepare(seed):
    binary = read_bounded("/bin/echo", MAX_BINARY)
    require(len(binary) >= 64 and binary[:6] == b"\x7fELF\x02\x01"
            and int.from_bytes(binary[18:20], "little") == 183, "expected arm64 ELF /bin/echo")
    if seed:
        ROOT.mkdir(mode=0o700)
    for name, _ in CASES:
        path = ROOT / name
        data = SCRIPT if name.startswith("script") else binary
        mode = 0o600 if name.endswith("-noexec") else 0o700
        if seed:
            # Exclusive files, closed before exec (no writable FD/ETXTBSY).
            with path.open("xb") as output:
                output.write(data)
            path.chmod(mode)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
                and (info.st_uid, info.st_gid) == (10001, 10001)
                and info.st_dev == ROOT.parent.stat().st_dev,
                "incorrect volume file identity or permissions")
        require(read_bounded(path, MAX_BINARY) == data, "volume executable bytes differ")
    return hashlib.sha256(binary).hexdigest()


def run_case(name, arguments):
    require((name, arguments) in CASES, "unknown direct-exec case")
    argv = [str(ROOT / name), *arguments]
    result = {"name": name, "argv": argv}
    # Regular-file capture + RLIMIT_FSIZE bound output before any host decoding.
    with tempfile.TemporaryFile(dir="/run") as output:
        try:
            # No shell=True, interpreter prefix, PATH lookup, or retry fallback.
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=output, close_fds=True, start_new_session=True)
        except OSError as error:
            return {**result, "errno": error.errno}
        try:
            result["exit"] = process.wait(timeout=5)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        output.seek(0)
        data = output.read(MAX_OUTPUT + 1)
        require(len(data) <= MAX_OUTPUT, "direct-exec output exceeds bound")
        return {**result, "output": data.decode()}


def main():
    def expired(signum, frame):
        raise TimeoutError("guest direct-exec deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(30)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BINARY, MAX_BINARY))
    result = {"schema": 1, "cases": []}
    code = 0
    try:
        require(sys.argv[1:] in (["seed"], ["peer"]), "unknown probe role")
        result.update(identity())
        result["mountinfo"] = read_bounded("/proc/self/mountinfo", 65536).decode()
        result["elf_sha256"] = prepare(sys.argv[1] == "seed")
        # Keep all four outcomes, including raw EINVAL, for backend-qualified diagnosis.
        for name, arguments in CASES:
            result["cases"].append(run_case(name, arguments))
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {str(error)[:1024]}"
        code = 1
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
