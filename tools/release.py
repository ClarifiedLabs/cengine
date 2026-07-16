#!/usr/bin/env python3
"""Create cengine application or kernel release commits and annotated tags."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass


PROJECT_FILE = pathlib.Path("cengine.xcodeproj/project.pbxproj")
KERNEL_RELEASE_FILE = pathlib.Path("Configuration/kernel-release")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
KERNEL_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[1-9]\d*)?$")
MARKETING_VERSION_RE = re.compile(r"(MARKETING_VERSION = )\d+\.\d+\.\d+(;)")
MARKETING_VERSION_VALUE_RE = re.compile(r"MARKETING_VERSION = (\d+\.\d+\.\d+);")


class ReleaseError(Exception):
    pass


@dataclass(frozen=True)
class ReleasePlan:
    current_version: str
    new_version: str
    tag: str


def run(root: pathlib.Path, *args: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), cwd=root, check=True, text=True,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
    )


def git(root: pathlib.Path, *args: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    return run(root, "git", *args, capture_output=capture_output)


def git_output(root: pathlib.Path, *args: str) -> str:
    return git(root, *args, capture_output=True).stdout


def repo_root() -> pathlib.Path:
    try:
        return pathlib.Path(git_output(pathlib.Path.cwd(), "rev-parse", "--show-toplevel").strip())
    except subprocess.CalledProcessError as error:
        raise ReleaseError("must be run from inside a git repository") from error


def parse_semver(version: str) -> tuple[int, int, int]:
    if version.startswith("v"):
        version = version[1:]
    if not SEMVER_RE.match(version):
        raise ReleaseError(f"invalid version {version!r}; expected X.Y.Z")
    return tuple(int(part) for part in version.split("."))  # type: ignore[return-value]


def current_version(root: pathlib.Path) -> str:
    output = git_output(root, "tag", "-l", "--sort=-version:refname", "v[0-9]*.[0-9]*.[0-9]*")
    return output.strip().splitlines()[0] if output.strip() else ""


def configured_kernel_release(root: pathlib.Path) -> str:
    path = root / KERNEL_RELEASE_FILE
    if not path.exists():
        raise ReleaseError(f"missing kernel release file: {KERNEL_RELEASE_FILE}")
    tag = path.read_text().strip()
    prefix = "kernel-v"
    if not tag.startswith(prefix) or not KERNEL_VERSION_RE.match(tag[len(prefix):]):
        raise ReleaseError(
            f"invalid kernel release in {KERNEL_RELEASE_FILE}: {tag!r}; "
            "expected kernel-vX.Y.Z or kernel-vX.Y.Z-N"
        )
    return tag


def project_version(root: pathlib.Path) -> str:
    path = root / PROJECT_FILE
    if not path.exists():
        raise ReleaseError(f"missing Xcode project file: {PROJECT_FILE}")
    match = MARKETING_VERSION_VALUE_RE.search(path.read_text())
    if not match:
        raise ReleaseError(f"no three-part MARKETING_VERSION entries found in {PROJECT_FILE}")
    return match.group(1)


def resolve_version(root: pathlib.Path, version_arg: str) -> str:
    if version_arg.startswith("v"):
        raise ReleaseError("VERSION must not start with 'v'; use X.Y.Z, patch, minor, or major")
    if SEMVER_RE.match(version_arg):
        return version_arg
    if version_arg not in {"patch", "minor", "major"}:
        raise ReleaseError("VERSION must be patch, minor, major, or an explicit X.Y.Z")
    current = current_version(root)
    if not current:
        return project_version(root)
    major, minor, patch = parse_semver(current)
    if version_arg == "major":
        return f"{major + 1}.0.0"
    if version_arg == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def build_plan(root: pathlib.Path, version_arg: str) -> ReleasePlan:
    new_version = resolve_version(root, version_arg)
    tag = f"v{new_version}"
    if git_output(root, "tag", "-l", tag).strip():
        raise ReleaseError(f"tag already exists: {tag}")
    return ReleasePlan(current_version=current_version(root) or "v0.0.0", new_version=new_version, tag=tag)


def resolve_kernel_version(version_arg: str) -> str:
    if version_arg.startswith(("v", "kernel-v")):
        raise ReleaseError(
            "kernel VERSION must not include a tag prefix; use X.Y.Z or X.Y.Z-N"
        )
    if not KERNEL_VERSION_RE.match(version_arg):
        raise ReleaseError("kernel VERSION must be an explicit X.Y.Z or X.Y.Z-N")
    return version_arg


def build_kernel_plan(root: pathlib.Path, version_arg: str) -> ReleasePlan:
    new_version = resolve_kernel_version(version_arg)
    tag = f"kernel-v{new_version}"
    if git_output(root, "tag", "-l", tag).strip():
        raise ReleaseError(f"tag already exists: {tag}")
    return ReleasePlan(
        current_version=configured_kernel_release(root),
        new_version=new_version,
        tag=tag,
    )


def ensure_clean_worktree(root: pathlib.Path) -> None:
    if git_output(root, "status", "--porcelain").strip():
        raise ReleaseError("working directory is not clean; commit or stash changes first")


def ensure_head_on_origin_main(root: pathlib.Path) -> None:
    try:
        git(root, "fetch", "origin", "main")
        run(root, "git", "merge-base", "--is-ancestor", "HEAD", "origin/main")
    except subprocess.CalledProcessError as error:
        raise ReleaseError("release commit must be present on origin/main before pushing a release tag") from error


def marketing_version_update(root: pathlib.Path, version: str) -> tuple[int, bool, str]:
    path = root / PROJECT_FILE
    original = path.read_text()
    updated, count = MARKETING_VERSION_RE.subn(rf"\g<1>{version}\2", original)
    if count == 0:
        raise ReleaseError(f"no three-part MARKETING_VERSION entries found in {PROJECT_FILE}")
    return count, updated != original, updated


def update_marketing_version(root: pathlib.Path, version: str) -> int:
    count, _, updated = marketing_version_update(root, version)
    (root / PROJECT_FILE).write_text(updated)
    return count


def kernel_release_update(root: pathlib.Path, version: str) -> tuple[bool, str]:
    path = root / KERNEL_RELEASE_FILE
    original = path.read_text()
    updated = f"kernel-v{version}\n"
    return updated != original, updated


def update_kernel_release(root: pathlib.Path, version: str) -> bool:
    changed, updated = kernel_release_update(root, version)
    (root / KERNEL_RELEASE_FILE).write_text(updated)
    return changed


def create_release(root: pathlib.Path, version_arg: str, dry_run: bool, push: bool) -> None:
    plan = build_plan(root, version_arg)
    print(f"Bumping cengine: {plan.current_version} -> v{plan.new_version}")
    print(f"Xcode project: {PROJECT_FILE} MARKETING_VERSION -> {plan.new_version}")
    print(f"Tag: {plan.tag}")
    if dry_run:
        _, changed, _ = marketing_version_update(root, plan.new_version)
        print("[dry-run] No files, commits, tags, or remotes were changed.")
        print(f"[dry-run] Would {'update' if changed else 'leave unchanged'} {PROJECT_FILE}.")
        print(f"[dry-run] Would create annotated tag: {plan.tag}")
        return

    ensure_clean_worktree(root)
    count = update_marketing_version(root, plan.new_version)
    git(root, "add", str(PROJECT_FILE))
    committed = False
    try:
        git(root, "diff", "--cached", "--quiet")
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:
            raise
        git(root, "commit", "-m", f"chore(release): bump version to v{plan.new_version}")
        committed = True
        print(f"Committed MARKETING_VERSION update ({count} entries).")
    if push:
        if committed:
            git(root, "push")
        ensure_head_on_origin_main(root)
    git(root, "tag", "-a", plan.tag, "-m", f"cengine v{plan.new_version}")
    print(f"Created tag: {plan.tag}")
    if push:
        git(root, "push", "origin", plan.tag)
        print(f"Pushed tag: {plan.tag}")


def create_kernel_release(root: pathlib.Path, version_arg: str, dry_run: bool, push: bool) -> None:
    plan = build_kernel_plan(root, version_arg)
    print(f"Bumping cengine kernel: {plan.current_version} -> {plan.tag}")
    print(f"Kernel release file: {KERNEL_RELEASE_FILE} -> {plan.tag}")
    print(f"Tag: {plan.tag}")
    if dry_run:
        changed, _ = kernel_release_update(root, plan.new_version)
        print("[dry-run] No files, commits, tags, or remotes were changed.")
        print(
            f"[dry-run] Would {'update' if changed else 'leave unchanged'} "
            f"{KERNEL_RELEASE_FILE}."
        )
        print(f"[dry-run] Would create annotated tag: {plan.tag}")
        return

    ensure_clean_worktree(root)
    changed = update_kernel_release(root, plan.new_version)
    git(root, "add", str(KERNEL_RELEASE_FILE))
    committed = False
    try:
        git(root, "diff", "--cached", "--quiet")
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:
            raise
        git(root, "commit", "-m", f"chore(release): bump kernel to {plan.tag}")
        committed = True
        print(f"Committed {KERNEL_RELEASE_FILE} update.")
    if changed != committed:
        raise ReleaseError(f"failed to stage {KERNEL_RELEASE_FILE} update")
    if push:
        if committed:
            git(root, "push")
        ensure_head_on_origin_main(root)
    git(root, "tag", "-a", plan.tag, "-m", f"cengine kernel {plan.new_version}")
    print(f"Created tag: {plan.tag}")
    if push:
        git(root, "push", "origin", plan.tag)
        print(f"Pushed tag: {plan.tag}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Release cengine to GitHub Releases.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--component", choices=("cengine", "kernel"), default="cengine")
    release_parser = subparsers.add_parser("release")
    release_parser.add_argument("--component", choices=("cengine", "kernel"), default="cengine")
    release_parser.add_argument("--version", required=True)
    release_parser.add_argument("--dry-run", action="store_true")
    release_parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    try:
        root = repo_root()
        if args.command == "list":
            label = "kernel release" if args.component == "kernel" else "release"
            tag = configured_kernel_release(root) if args.component == "kernel" else current_version(root)
            print(f"Current {label} tag:\n")
            print(f"  {tag or '(no tags)'}")
        elif args.component == "kernel":
            create_kernel_release(root, args.version, args.dry_run, args.push)
        else:
            create_release(root, args.version, args.dry_run, args.push)
    except ReleaseError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(f"Error: command failed with exit code {error.returncode}: {' '.join(error.cmd)}", file=sys.stderr)
        return error.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
