from __future__ import annotations

import pathlib


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def read(path: pathlib.Path) -> str:
    if not path.exists():
        raise AssertionError(f"missing file: {path}")
    return path.read_text()


def require_contains(contents: str, needle: str, label: str) -> None:
    if needle not in contents:
        raise AssertionError(f"{label} is missing {needle!r}")


def require_absent(contents: str, needle: str, label: str) -> None:
    if needle in contents:
        raise AssertionError(f"{label} unexpectedly contains {needle!r}")
