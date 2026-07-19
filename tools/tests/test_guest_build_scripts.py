import hashlib
import os
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

    def test_guest_tests_prefer_an_available_host_toolchain(self) -> None:
        script = (ROOT / "Scripts" / "test-guest.sh").read_text()

        self.assertIn('command -v go', script)
        self.assertIn('go env GOOS)" = linux', script)
        self.assertIn("exec go test ./...", script)

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


if __name__ == "__main__":
    unittest.main()
