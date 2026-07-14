#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "Tests" / "Compatibility"))

from harness import (  # noqa: E402
    compatibility_root_owned_by,
    compatibility_runtime_processes,
    terminate_compatibility_runtime,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset cengine-owned Docker compatibility runtime state")
    parser.add_argument(
        "--binary",
        type=pathlib.Path,
        default=REPO_ROOT / ".build/xcode-derived/Build/Products/Debug/cengine",
    )
    parser.add_argument(
        "--root",
        action="append",
        type=pathlib.Path,
        default=[],
        help="also terminate runtime processes associated with this explicit engine root",
    )
    parser.add_argument(
        "--system-networking",
        action="store_true",
        help="restart cengine's helper and macOS NetworkSharing to recover leaked vmnet reservations",
    )
    args = parser.parse_args()

    binary = args.binary.resolve()

    stopped = terminate_compatibility_runtime(binary)
    for root in args.root:
        stopped.extend(terminate_compatibility_runtime(binary, roots=(root,)))

    temporary_root = pathlib.Path(tempfile.gettempdir())
    removed = 0
    for directory in temporary_root.glob("cengine-compat-*"):
        if directory.is_dir() and compatibility_root_owned_by(directory, binary):
            shutil.rmtree(directory)
            removed += 1

    if args.system_networking:
        command = (
            "/usr/bin/pkill -9 -x InternetSharing 2>/dev/null || true; "
            "/bin/launchctl kill SIGKILL system/dev.cengine.network-helper 2>/dev/null || true"
        )
        subprocess.run(
            [
                "osascript",
                "-e",
                f'do shell script "{command}" with administrator privileges',
            ],
            check=True,
        )
        time.sleep(2)

    remaining_processes = compatibility_runtime_processes(
        binary,
        roots=tuple(root.resolve() for root in args.root),
    )
    remaining_roots = [
        directory
        for directory in temporary_root.glob("cengine-compat-*")
        if directory.is_dir() and compatibility_root_owned_by(directory, binary)
    ]
    if remaining_processes or remaining_roots:
        for process in remaining_processes:
            print(f"compatibility runtime still running: {process.pid} {process.command}", file=sys.stderr)
        for directory in remaining_roots:
            print(f"compatibility root still present: {directory}", file=sys.stderr)
        raise SystemExit("compatibility runtime reset did not reach a clean state")

    print(
        "compatibility runtime clean: "
        f"stopped {len(stopped)} processes, removed {removed} roots, "
        "verified no owned processes or temporary roots remain"
    )


if __name__ == "__main__":
    main()
