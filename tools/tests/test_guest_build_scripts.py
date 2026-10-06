import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class GuestBuildScriptTests(unittest.TestCase):
    def test_guest_build_bootstraps_a_checksum_pinned_go_toolchain(self) -> None:
        builder = (ROOT / "Scripts" / "build-guest-assets.sh").read_text()
        toolchain = (ROOT / "Scripts" / "ensure-go-toolchain.sh").read_text()

        self.assertIn('ensure-go-toolchain.sh', builder)
        self.assertIn('VERSION=1.26.5', toolchain)
        self.assertIn('PLATFORM=darwin-arm64', toolchain)
        self.assertIn('PLATFORM=linux-arm64', toolchain)
        self.assertIn('https://go.dev/dl/go$VERSION.$PLATFORM.tar.gz', toolchain)
        self.assertIn('shasum -a 256 -c -', toolchain)
        self.assertIn('efb87ff28af9a188d0536ef5d42e63dd52ba8263cd7344a993cc48dd11dedb6a', toolchain)
        self.assertIn('fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49', toolchain)

    def test_guest_bootstrap_metadata_binds_both_completed_initramfs_images(self) -> None:
        builder = (ROOT / "Scripts/build-guest-assets.sh").read_text()
        metadata_start = builder.index('python3 - "$OUTPUT"')
        self.assertLess(builder.index('"$OUTPUT/container-initramfs.cpio.gz"'), metadata_start)
        self.assertLess(builder.index('"$OUTPUT/storage-initramfs.cpio.gz"'), metadata_start)
        # Execute only the real metadata/checksum tail over fixture bytes: no
        # toolchain, guest image build, Docker, VM, or elevation is involved.
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            images = {
                "vmlinux": b"kernel fixture",
                "container-initramfs.cpio.gz": b"container fixture",
                "storage-initramfs.cpio.gz": b"storage fixture",
            }
            for name, data in images.items():
                (output / name).write_bytes(data)
            environment = dict(os.environ, OUTPUT=str(output))
            tail = builder[metadata_start:]
            subprocess.run(["sh", "-eu"], input=tail, env=environment, text=True, check=True)
            expected = {
                "schemaVersion": 1,
                "protocolVersion": 1,
                "storageServiceBootVersion": 2,
                "workloadStorageBootVersion": 1,
                "storageLifecycleVersion": 2,
                "containerInitramfsSHA256": hashlib.sha256(images["container-initramfs.cpio.gz"]).hexdigest(),
                "storageInitramfsSHA256": hashlib.sha256(images["storage-initramfs.cpio.gz"]).hexdigest(),
            }
            self.assertEqual(json.loads((output / "disk-bootstrap.json").read_text()), expected)
            checksums = dict(line.split()[::-1] for line in (output / "SHA256SUMS").read_text().splitlines())
            self.assertEqual(set(checksums), set(images) | {"disk-bootstrap.json"})
            for name, digest in checksums.items():
                self.assertEqual(digest, hashlib.sha256((output / name).read_bytes()).hexdigest())
            (output / "storage-initramfs.cpio.gz").write_bytes(b"rebuilt storage fixture")
            subprocess.run(["sh", "-eu"], input=tail, env=environment, text=True, check=True)
            updated = json.loads((output / "disk-bootstrap.json").read_text())
            self.assertEqual(updated["containerInitramfsSHA256"], expected["containerInitramfsSHA256"])
            self.assertNotEqual(updated["storageInitramfsSHA256"], expected["storageInitramfsSHA256"])

    def test_ordinary_guest_builds_are_closed_offline_without_ambient_tags(self):
        # Regression: ordinary guest builds used to inherit ambient Go config
        # and -tags. Production binaries now compile in the same closed,
        # offline, vendor-only environment as explicit compatibility profiles,
        # with a fresh private cache and a selected-input audit.
        builder = (ROOT / "Scripts/build-guest-assets.sh").read_text()
        self.assertNotIn("PREPARE_GO_CACHE", builder)
        self.assertIn('GUEST_GO_CACHE=$(mktemp -d', builder)
        self.assertLess(builder.index('GUEST_GO_CACHE=$(mktemp -d'), builder.index("guest_go() {"))
        wrapper = builder[builder.index("guest_go() {"):builder.index('mkdir -p "$BINARY_OUTPUT/out"')]
        self.assertNotIn('if [ -n "$PREPARE_COMPATIBILITY_PROFILE" ]', wrapper)
        for needle in ("-mod=vendor", "GOENV=off", "GOFLAGS=", "GOWORK=off", "GO111MODULE=on",
                       "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOARM64=v8.0",
                       "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64"):
            self.assertIn(needle, wrapper)
        selection = builder[builder.index('case "$1" in'):builder.index("esac", builder.index('case "$1" in'))]
        self.assertNotIn("-tags", selection)
        build_section = builder[builder.index('cd "$ROOT/Guest"'):builder.index('guest_go build "$@"')]
        self.assertNotIn("PREPARE_COMPATIBILITY_PROFILE", build_section)
        self.assertIn('audit-inputs "$ROOT"', build_section)

    def test_guest_tests_prefer_an_available_host_toolchain(self) -> None:
        script = (ROOT / "Scripts" / "test-guest.sh").read_text()

        self.assertIn('command -v go', script)
        self.assertIn('go env GOOS)" = linux', script)
        self.assertIn("exec unshare --mount --propagation private setsid --wait go test -skip '^TestNative(MountedManagedV3|IssuedDataTLS)' \"$@\" -p=1 -count=1 -timeout=20m -json", script)
        # All entry paths must run uncached, serialize scratch users and retain
        # per-test JSON evidence under an explicit finite package deadline.
        self.assertEqual(script.count("-p=1 -count=1 -timeout=20m -json"), 3)

    def test_native_guest_tests_require_root_and_ext4_before_running_go(self) -> None:
        # Exercise the real script with stubbed host tools, without elevation.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, body in {
                "go": ('case "$1" in env) echo linux;; list) '
                       'printf "%s\\n" dev.cengine/guest/internal/storageworker '
                       'dev.cengine/guest/internal/storagemanaged dev.cengine/guest/internal/storageserver;; '
                       '*) echo "go:$*"; exit "${TEST_GO_STATUS:-0}";; esac'),
                "id": 'case "$1" in -u) echo "$TEST_UID";; -g) echo "$TEST_GID";; esac',
                "findmnt": 'echo "$TEST_FS"',
                "setsid": 'test "$1" = --wait || exit 1; shift; echo "setsid"; exec "$@"',
                "unshare": ('test "$1" = --mount && test "$2" = --propagation '
                            '&& test "$3" = private || exit 1; '
                            'shift 3; echo "private mount namespace"; exec "$@"'),
            }.items():
                tool = directory / name
                tool.write_text("#!/bin/sh\n" + body + "\n")
                tool.chmod(0o755)
            for uid, gid, filesystem, status, diagnostic in (
                ("1001", "0", "ext4", 2, "require Linux root uid/gid"),
                ("0", "1001", "ext4", 2, "require Linux root uid/gid"),
                ("0", "0", "tmpfs", 2, "require TMPDIR on ext4"),
                ("0", "0", "ext4", 0, "host kernel:"),
            ):
                with self.subTest(uid=uid, gid=gid, filesystem=filesystem):
                    environment = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                                       TEST_UID=uid, TEST_GID=gid, TEST_FS=filesystem)
                    result = subprocess.run(["sh", str(ROOT / "Scripts/test-guest.sh")],
                                            env=environment, text=True, capture_output=True)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertIn(diagnostic, result.stderr)
                    if status:
                        self.assertNotIn("go:test", result.stdout)
                        self.assertNotIn("private mount namespace", result.stdout)
                    else:
                        self.assertIn("private mount namespace\nsetsid\n", result.stdout)
                        self.assertIn("setsid\n", result.stdout)
                        self.assertIn("go:test -skip ^TestNative(MountedManagedV3|IssuedDataTLS) dev.cengine/guest/internal/storageworker", result.stdout)
                        self.assertNotIn("storagemanaged", result.stdout)
                        self.assertNotIn("storageserver", result.stdout)
            environment.update(TEST_UID="0", TEST_GID="0", TEST_FS="ext4", TEST_GO_STATUS="7")
            result = subprocess.run(["sh", str(ROOT / "Scripts/test-guest.sh")],
                                    env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 7, "guest test failures must fail CI")

    def test_guest_test_container_supplies_fixture_tree_scratch_and_fuse(self) -> None:
        script = (ROOT / "Scripts" / "test-guest.sh").read_text()

        self.assertIn('--mount "type=bind,src=$2/Guest,dst=/src/Guest,readonly"', script)
        self.assertIn('--mount "type=bind,src=$2/Tests,dst=/src/Tests,readonly"', script)
        self.assertIn('--mount "type=bind,src=$3,dst=/guest-fixtures,readonly"', script)
        self.assertIn('--workdir /src/Guest', script)
        self.assertIn('--mount type=volume,destination=/scratch,volume-nocopy=true', script)
        self.assertIn('--env TMPDIR=/scratch', script)
        self.assertIn('--privileged', script)
        self.assertIn('mknod /dev/fuse c 10 229', script)
        self.assertIn('printf "1\\n" > /proc/sys/fs/protected_hardlinks', script)
        self.assertIn('printf "Y\\n" > /sys/module/fuse/parameters/enable_uring', script)
        self.assertIn('mount -t fusectl fusectl /sys/fs/fuse/connections', script)
        self.assertIn('d4293e6536e184abd383c258104765bbdec783faa7025cde93c797c97067a632', script)
        self.assertIn('mount -o ro,bind /guest-fixtures/fsx /fsx', script)
        self.assertIn("setsid go test -skip '^TestNativeMountedManagedV3FsxGraceful$' ./...", script)
        self.assertIn('pinned fsx fixture absent; skipping TestNativeMountedManagedV3FsxGraceful', script)
        self.assertIn('exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-', script)
        self.assertIn('setsid go test ./...', script)
        self.assertIn("exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-\n            # Keep the test binary out of the PID 1 process group", script)
        self.assertNotIn('--device /dev/fuse', script)
        self.assertNotIn('--tmpfs /scratch', script)

    def test_e2fsprogs_build_uses_static_target_with_prerequisites(self) -> None:
        script = (ROOT / "Scripts" / "build-e2fsprogs.sh").read_text()

        self.assertIn('make -j"$(nproc)" libs', script)
        self.assertIn('make -C misc -j"$(nproc)" mke2fs.static', script)
        self.assertIn('install -m 0755 misc/mke2fs.static /mke2fs', script)

    def test_kernel_build_includes_required_runtime_features_as_builtins(self) -> None:
        config = (ROOT / "Configuration" / "cengine-kernel.fragment").read_text()
        compiler = (ROOT / "Scripts" / "compile-kernel-in-guest.sh").read_text()
        image = (ROOT / "Configuration" / "kernel-build-image").read_text().strip()
        settings = set(config.splitlines())
        required = {
            "CONFIG_BLK_CGROUP=y",
            "CONFIG_BLK_DEV_THROTTLING=y",
            "CONFIG_FUSE_FS=y",
            "CONFIG_VIRTIO_FS=y",
            "CONFIG_OVERLAY_FS=y",
            "CONFIG_FS_VERITY=y",
            "CONFIG_VETH=y",
            "CONFIG_BRIDGE_NETFILTER=y",
            "CONFIG_NF_TABLES=y",
            "CONFIG_NFT_NUMGEN=y",
            "CONFIG_NFT_COMPAT=y",
            "CONFIG_NFT_MASQ=y",
            "CONFIG_NFT_NAT=y",
            "CONFIG_NETFILTER_XTABLES=y",
            "CONFIG_IP_NF_IPTABLES=y",
            "CONFIG_IP6_NF_IPTABLES=y",
            "CONFIG_IP_VS=y",
            "CONFIG_VXLAN=y",
            "CONFIG_MACVLAN=y",
            "CONFIG_IPVLAN=y",
        }

        self.assertRegex(image, r"^debian:trixie-slim@sha256:[0-9a-f]{64}$")
        self.assertTrue(required <= settings, required - settings)
        self.assertFalse(any(line.endswith("=m") for line in settings))
        self.assertIn('done < /fragment', compiler)
        self.assertIn('kernel option did not resolve as built-in', compiler)

    def test_kernel_build_uses_buildx_without_cengine_virtualization(self) -> None:
        builder = (ROOT / "Scripts" / "build-kernel-linux.sh").read_text()

        self.assertIn('docker_cli "$@"', builder)
        self.assertIn('--platform linux/arm64', builder)
        self.assertIn('compile-kernel-in-guest.sh', builder)
        self.assertNotIn('run-isolated-cengine.sh', builder)

    def test_kernel_build_honors_standard_docker_context_and_resource_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "linux"
            output = root / "output"
            cache = root / "cache"
            binary = root / "bin"
            arguments = root / "docker-arguments"
            source.mkdir()
            binary.mkdir()
            (source / "Makefile").write_text("all:\n")
            docker = binary / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in *\"buildx version\"*) exit 0;; esac\n"
                "printf '%s\\n' \"$@\" > \"$CENGINE_TEST_DOCKER_ARGUMENTS\"\n"
            )
            docker.chmod(0o755)
            environment = os.environ.copy()
            environment.update({
                "PATH": f"{binary}:{environment['PATH']}",
                "KERNEL_SOURCE": str(source),
                "CENGINE_GUEST_OUTPUT": str(output),
                "CENGINE_GUEST_CACHE": str(cache),
                "CENGINE_TEST_DOCKER_ARGUMENTS": str(arguments),
            })

            subprocess.run(
                [str(ROOT / "Scripts" / "build-kernel-linux.sh")],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            default_arguments = arguments.read_text().splitlines()
            self.assertEqual(default_arguments[:2], ["buildx", "build"])
            self.assertNotIn("--context", default_arguments)
            self.assertIn("CENGINE_KERNEL_BUILD_JOBS=auto", default_arguments)
            self.assertNotIn("--resource", default_arguments)

            environment.update({
                "CENGINE_TOOLCHAIN_DOCKER_CONTEXT": "developer-context",
                "CENGINE_KERNEL_BUILD_CPUS": "8",
                "CENGINE_KERNEL_BUILD_MEMORY": "16g",
            })
            subprocess.run(
                [str(ROOT / "Scripts" / "build-kernel-linux.sh")],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            limited_arguments = arguments.read_text().splitlines()
            self.assertEqual(
                limited_arguments[:4],
                ["--context", "developer-context", "buildx", "build"],
            )
            self.assertIn("CENGINE_KERNEL_BUILD_JOBS=8", limited_arguments)
            self.assertIn("cpu-quota=800000", limited_arguments)
            self.assertIn("memory=16g", limited_arguments)

    def kernel_fixture(self, root: Path) -> tuple[Path, Path, dict[str, str]]:
        for name in ("Scripts", "Configuration"):
            shutil.copytree(ROOT / name, root / name)
        source = root / "cached-linux"
        source.mkdir()
        (source / "Makefile").write_text("original\n")
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "add", "Makefile"], check=True)
        subprocess.run([
            "git", "-C", str(source), "-c", "user.name=Test", "-c",
            "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-qm", "fixture",
        ], check=True)
        commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True)
        (root / "Configuration/kernel-commit").write_text(commit)
        patches = root / "Configuration/kernel-patches"
        (patches / "series").write_text("first.patch\nsecond.patch\n")
        for name, before, after in (("first", "original", "intermediate"), ("second", "intermediate", "patched")):
            (patches / f"{name}.patch").write_text(
                "From: cengine test\nSubject: [PATCH] fixture\n\n"
                "diff --git a/Makefile b/Makefile\n"
                f"--- a/Makefile\n+++ b/Makefile\n@@ -1 +1 @@\n-{before}\n+{after}\n"
            )
        (root / "Scripts/build-kernel-linux.sh").write_text(
            '#!/bin/sh\nset -eu\n'
            'printf "%s\\n" "$KERNEL_SOURCE" > "$CENGINE_GUEST_OUTPUT/build-source"\n'
            'test "$(cat "$KERNEL_SOURCE/Makefile")" = patched\n'
            'cp "$KERNEL_SOURCE/Makefile" "$CENGINE_GUEST_OUTPUT/vmlinux"\n'
        )
        environment = os.environ.copy()
        environment.update({
            "KERNEL_SOURCE": str(source),
            "CENGINE_GUEST_CACHE": str(root / "cache"),
            "CENGINE_GUEST_OUTPUT": str(root / "output"),
            "CENGINE_HOST_OS": "Linux",
        })
        return source, patches, environment

    def test_kernel_patches_apply_in_order_without_touching_dirty_source(self) -> None:
        # Nest under a Git repository, as real .build/ is: git apply must not
        # discover that parent and silently skip all kernel-relative paths.
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            subprocess.run(["git", "init", "-q", str(parent)], check=True)
            root = parent / "project"
            source, _, environment = self.kernel_fixture(root)
            (source / "Makefile").write_text("developer changes\n")
            (source / "untracked").write_text("preserve me\n")
            subprocess.run([str(root / "Scripts/build-kernel.sh")], env=environment,
                           check=True, capture_output=True, text=True)
            output = root / "output"
            self.assertEqual((output / "vmlinux").read_text(), "patched\n")
            self.assertEqual((source / "Makefile").read_text(), "developer changes\n")
            self.assertEqual((source / "untracked").read_text(), "preserve me\n")
            self.assertNotEqual(Path((output / "build-source").read_text().strip()), source)
            self.assertFalse(Path((output / "build-source").read_text().strip()).exists())
            self.assertEqual(len((output / "kernel-input.sha256").read_text().strip()), 64)
            self.assertEqual(list((root / "cache").glob("kernel-build.*")), [])

    def test_kernel_rejected_patch_does_not_build_or_stamp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, patches, environment = self.kernel_fixture(root)
            (patches / "second.patch").write_text(
                "--- a/Makefile\n+++ b/Makefile\n@@ -1 +1 @@\n-not present\n+bad\n"
            )
            output = root / "output"
            output.mkdir()
            (output / "kernel-input.sha256").write_text("old stamp\n")
            result = subprocess.run([str(root / "Scripts/build-kernel.sh")], env=environment,
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("patch does not apply", result.stderr)
            self.assertFalse((output / "vmlinux").exists())
            self.assertEqual((output / "kernel-input.sha256").read_text(), "old stamp\n")
            self.assertEqual((source / "Makefile").read_text(), "original\n")
            self.assertEqual(list((root / "cache").glob("kernel-build.*")), [])

    def test_kernel_patch_helper_refuses_an_ordinary_source_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _ = self.kernel_fixture(root)
            result = subprocess.run([str(root / "Scripts/apply-kernel-patches.sh"), str(source)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not exported by build-kernel.sh", result.stderr)
            self.assertEqual((source / "Makefile").read_text(), "original\n")

    def test_kernel_build_refuses_a_stamp_when_inputs_change_during_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, patches, environment = self.kernel_fixture(root)
            builder = root / "Scripts/build-kernel-linux.sh"
            with builder.open("a") as stream:
                stream.write(f'printf "changed\\n" >> "{patches / "first.patch"}"\n')
            result = subprocess.run([str(root / "Scripts/build-kernel.sh")], env=environment,
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("inputs changed during build", result.stderr)
            self.assertFalse((root / "output/kernel-input.sha256").exists())

    def test_kernel_stamp_covers_patch_content_order_and_application_logic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, patches, _ = self.kernel_fixture(root)
            script = root / "Scripts/kernel-input-sha256.sh"
            def digest() -> str:
                return subprocess.check_output([str(script)], text=True).strip()
            previous = digest()
            for path, extra in ((patches / "first.patch", "\n"),
                                (root / "Scripts/build-kernel.sh", "\n# change\n"),
                                (root / "Scripts/apply-kernel-patches.sh", "\n# change\n")):
                with path.open("a") as stream:
                    stream.write(extra)
                current = digest()
                self.assertNotEqual(current, previous, str(path))
                previous = current
            (patches / "series").write_text("second.patch\nfirst.patch\n")
            self.assertNotEqual(digest(), previous)
            (patches / "first.patch").unlink()
            result = subprocess.run([str(script)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            (patches / "series").write_text("../escape.patch\n")
            result = subprocess.run([str(script)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid kernel patch name", result.stderr)

    def test_kernel_release_fetch_verifies_checksums_and_build_inputs(self) -> None:
        expected_input = subprocess.run(
            [str(ROOT / "Scripts" / "kernel-input-sha256.sh")],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / "release"
            output = root / "output"
            release.mkdir()
            assets = {
                "cengine-kernel-arm64": b"test ARM64 kernel\n",
                "kernel-input.sha256": f"{expected_input}\n".encode(),
            }
            for name, data in assets.items():
                (release / name).write_bytes(data)
            (release / "SHA256SUMS").write_text("".join(
                f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in assets.items()
            ))
            environment = os.environ.copy()
            environment.update({
                "CENGINE_GUEST_OUTPUT": str(output),
                "CENGINE_GUEST_CACHE": str(root / "cache"),
                "CENGINE_KERNEL_RELEASE_BASE_URL": release.as_uri(),
            })
            subprocess.run(
                [str(ROOT / "Scripts" / "fetch-kernel.sh")],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual((output / "vmlinux").read_bytes(), assets["cengine-kernel-arm64"])
            self.assertEqual((output / "kernel-input.sha256").read_text().strip(), expected_input)
            receipt = json.loads((output / "kernel-origin.json").read_text())
            self.assertEqual(receipt["origin"], "custom-release")
            self.assertEqual(receipt["sha256"], hashlib.sha256(assets["cengine-kernel-arm64"]).hexdigest())

    def test_local_kernel_override_is_installed_without_a_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            local = root / "Image"
            output = root / "output"
            local.write_bytes(b"local ARM64 kernel\n")
            environment = os.environ.copy()
            environment.update({
                "CENGINE_GUEST_OUTPUT": str(output),
                "CENGINE_GUEST_CACHE": str(root / "cache"),
                "CENGINE_LOCAL_KERNEL": str(local),
            })
            subprocess.run(
                [str(ROOT / "Scripts" / "fetch-kernel.sh")],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual((output / "vmlinux").read_bytes(), local.read_bytes())
            receipt = json.loads((output / "kernel-origin.json").read_text())
            self.assertEqual(receipt["origin"], "local")


if __name__ == "__main__":
    unittest.main()
