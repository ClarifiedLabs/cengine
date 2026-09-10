#!/usr/bin/env python3
"""Exercise a substituted postinstall and inspect a fixture PKG; never install it."""
from __future__ import annotations

import json
import os
import pathlib
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "Scripts/Installer/postinstall"
PKGBUILD = pathlib.Path("/usr/bin/pkgbuild")
PKGUTIL = pathlib.Path("/usr/sbin/pkgutil")

# All downstream execution is restricted to these fixtures, even if the script
# accidentally passes a real executable. The app itself is never executed.
MOCK = r'''
import json
import os
import pathlib
import stat
import sys

name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
null_device = os.stat(os.devnull).st_rdev
with open(os.environ["MOCK_LOG"], "a") as log:
    log.write(json.dumps({
        "argv": [name, *args],
        "null_stdio": [
            stat.S_ISCHR(os.fstat(fd).st_mode) and os.fstat(fd).st_rdev == null_device
            for fd in range(3)
        ],
    }) + "\n")


def fail_if_requested(knob):
    status = int(os.environ.get(knob, "0"))
    if status:
        sys.exit(status)


def exec_mock(command, argv):
    expected = str(pathlib.Path(sys.argv[0]).parent / command)
    if not argv or argv[0] != expected:
        raise RuntimeError("refusing to execute non-fixture command: " + repr(argv))
    os.execv(expected, [expected, *argv[1:]])


if name == "id":
    fail_if_requested("MOCK_ID_STATUS")
    print(os.environ.get("MOCK_UID", "0"))
elif name == "stat":
    fail_if_requested("MOCK_STAT_STATUS")
    print(os.environ.get("MOCK_CONSOLE_UID", "502"))
elif name == "launchctl" and args[:1] == ["print"]:
    print("GUI probe stdout")
    print("GUI probe stderr", file=sys.stderr)
    fail_if_requested("MOCK_GUI_STATUS")
elif name == "pgrep":
    sys.exit(int(os.environ.get("MOCK_PGREP_STATUS", "1")))
elif name == "launchctl" and args[:1] == ["asuser"]:
    fail_if_requested("MOCK_ASUSER_STATUS")
    exec_mock("sudo", args[2:])
elif name == "sudo":
    fail_if_requested("MOCK_SUDO_STATUS")
    if args[:3] != ["-n", "-H", "-u"] or args[4:5] != ["--"]:
        raise RuntimeError("unexpected sudo arguments: " + repr(args))
    exec_mock("open", args[5:])
elif name == "open":
    print("open stdout")
    print("open stderr", file=sys.stderr)
    fail_if_requested("MOCK_OPEN_STATUS")
else:
    raise RuntimeError("unexpected mock invocation: " + repr(sys.argv))
'''


class InstallerBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cengine-installer-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.commands = self.root / "mock commands"
        self.commands.mkdir()
        self.app = self.root / "Applications with spaces/cengine.app"
        self.executable = self.app / "Contents/MacOS/cengine"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_text("#!/bin/sh\nexit 99\n")
        self.executable.chmod(0o755)
        self.log = self.root / "calls.jsonl"

        source = SCRIPT.read_text()
        for path, count in {
            "/usr/bin/id": 1,
            "/usr/bin/stat": 1,
            "/bin/launchctl": 2,
            "/usr/bin/pgrep": 1,
            "/usr/bin/sudo": 1,
            "/usr/bin/open": 1,
        }.items():
            self.assertEqual(source.count(path), count, f"unsafe substitution: {path}")
            mock = self.commands / pathlib.Path(path).name
            mock.write_text(f"#!{sys.executable}\n" + MOCK)
            mock.chmod(0o755)
            source = source.replace(path, shlex.quote(str(mock)))
        assignment = "app=/Applications/cengine.app"
        self.assertEqual(source.count(assignment), 1, "app substitution did not match")
        source = source.replace(assignment, "app=" + shlex.quote(str(self.app)))
        # Fail closed if another absolute OS command is introduced. PATH below
        # also prevents an unqualified command from resolving to a real utility.
        self.assertNotRegex("\n".join(source.splitlines()[1:]), r"/(?:usr/(?:bin|sbin)|bin|sbin)/")
        self.script = self.root / "postinstall"
        self.script.write_text(source)

    def handoff_calls(self, uid: str = "502") -> list[list[str]]:
        open_args = [str(self.app), "--args", "--opened-by-installer"]
        sudo_args = ["-n", "-H", "-u", f"#{uid}", "--", str(self.commands / "open"), *open_args]
        return [
            ["id", "-u"],
            ["stat", "-f", "%u", "/dev/console"],
            ["launchctl", "print", f"gui/{uid}"],
            ["pgrep", "-u", uid, "-f",
             "^/Applications/cengine[.]app/Contents/MacOS/cengine([[:space:]]|$)"],
            ["launchctl", "asuser", uid, str(self.commands / "sudo"), *sudo_args],
            ["sudo", *sudo_args],
            ["open", *open_args],
        ]

    def assert_run(
        self,
        expected: list[list[str]],
        *,
        arguments: tuple[str, ...] = ("fixture.pkg", "/", "/"),
        warning: bool = False,
        reopen: bool = False,
        **knobs: str,
    ) -> list[dict]:
        self.log.write_text("")
        result = subprocess.run(
            ["/bin/sh", self.script, *arguments],
            input="installer stdin must not reach the handoff\n",
            capture_output=True, text=True, timeout=10,
            env={
                "PATH": str(self.commands), "HOME": str(self.root),
                "MOCK_LOG": str(self.log), **knobs,
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        if reopen:
            expected_stderr = "cengine was installed. Quit and reopen cengine to finish the upgrade.\n"
        elif warning:
            expected_stderr = (
                "cengine was installed, but could not be opened automatically. "
                "Open /Applications/cengine.app to finish setup or resume the engine.\n"
            )
        else:
            expected_stderr = ""
        self.assertEqual(result.stderr, expected_stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([call["argv"] for call in calls], expected)
        return calls

    def test_success_handoff_arguments_and_devnull_stdio(self) -> None:
        for uid in ("501", "502", "1502"):
            with self.subTest(uid=uid):
                calls = self.assert_run(self.handoff_calls(uid), MOCK_CONSOLE_UID=uid)
                self.assertEqual(calls[2]["null_stdio"], [False, True, True])
                for call in calls[3:]:
                    self.assertEqual(call["null_stdio"], [True, True, True], call)

    def test_inherited_user_and_sudo_user_do_not_select_session(self) -> None:
        for user, sudo_user in (("root", "administrator"), ("someone-else", "root")):
            with self.subTest(user=user, sudo_user=sudo_user):
                self.assert_run(
                    self.handoff_calls("777"), MOCK_CONSOLE_UID="777",
                    USER=user, SUDO_USER=sudo_user,
                )

    def test_missing_or_nonboot_target_does_nothing(self) -> None:
        for arguments in (
            (), ("fixture.pkg",), ("fixture.pkg", "/"),
            ("fixture.pkg", "/", ""), ("fixture.pkg", "/", "/Volumes/Other Disk"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_run([], arguments=arguments)

    def test_nonroot_does_not_probe_console_or_launch(self) -> None:
        self.assert_run(self.handoff_calls()[:1], MOCK_UID="501")

    def test_missing_app_does_not_probe_console_or_launch(self) -> None:
        self.executable.unlink()
        self.assert_run(self.handoff_calls()[:1])

    def test_nonexecutable_app_does_not_probe_console_or_launch(self) -> None:
        self.executable.chmod(0o644)
        self.assert_run(self.handoff_calls()[:1])

    def test_failed_identity_or_console_lookup_is_nonfatal(self) -> None:
        for knob, count in (("MOCK_ID_STATUS", 1), ("MOCK_STAT_STATUS", 2)):
            with self.subTest(command=knob):
                self.assert_run(self.handoff_calls()[:count], **{knob: "1"})

    def test_malformed_or_system_console_uid_does_not_launch(self) -> None:
        for uid in ("", "root", "501x", " 501", "501 ", "+501", "-1", "501\n502", "0", "1", "500"):
            with self.subTest(uid=uid):
                self.assert_run(self.handoff_calls()[:2], MOCK_CONSOLE_UID=uid)

    def test_missing_gui_domain_does_not_launch(self) -> None:
        self.assert_run(self.handoff_calls()[:3], MOCK_GUI_STATUS="1")

    def test_running_app_or_failed_probe_requires_manual_reopen(self) -> None:
        for status in ("0", "2", "3"):
            with self.subTest(status=status):
                self.assert_run(self.handoff_calls()[:4], reopen=True, MOCK_PGREP_STATUS=status)

    def test_handoff_failures_warn_without_root_fallback(self) -> None:
        for knob, count in (
            ("MOCK_ASUSER_STATUS", 5), ("MOCK_SUDO_STATUS", 6), ("MOCK_OPEN_STATUS", 7),
        ):
            with self.subTest(command=knob):
                self.assert_run(self.handoff_calls()[:count], warning=True, **{knob: "42"})


@unittest.skipUnless(
    sys.platform == "darwin" and os.access(PKGBUILD, os.X_OK) and os.access(PKGUTIL, os.X_OK),
    "macOS pkgbuild and pkgutil are required to inspect a fixture PKG",
)
class InstallerPackageTests(unittest.TestCase):
    def test_real_postinstall_is_registered_and_archived_executable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cengine-installer-pkg-") as directory:
            root = pathlib.Path(directory)
            payload = root / "payload"
            payload.mkdir()
            (payload / "fixture.txt").write_text("Installer test fixture; never install.\n")
            package = root / "fixture.pkg"
            expanded = root / "expanded"
            # Build and expand only: no installer, sudo, app, or service invocation.
            for command in (
                [PKGBUILD, "--root", payload, "--scripts", SCRIPT.parent,
                 "--identifier", "dev.cengine.installer-test", "--version", "1",
                 "--install-location", "/", package],
                [PKGUTIL, "--expand-full", package, expanded],
            ):
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            registrations = ET.parse(expanded / "PackageInfo").findall("scripts/postinstall")
            self.assertEqual(len(registrations), 1)
            self.assertEqual(registrations[0].get("file"), "./postinstall")
            archived = expanded / "Scripts/postinstall"
            self.assertEqual(archived.read_bytes(), SCRIPT.read_bytes())
            self.assertEqual(stat.S_IMODE(archived.stat().st_mode), stat.S_IMODE(SCRIPT.stat().st_mode))
            self.assertTrue(archived.stat().st_mode & 0o111, "archived postinstall must be executable")


if __name__ == "__main__":
    unittest.main()
